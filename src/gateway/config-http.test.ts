import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const TEST_GATEWAY_TOKEN = "test-gateway-token-1234567890";

let cfg: Record<string, unknown> = {};

vi.mock("../config/config.js", () => ({
  loadConfig: () => cfg,
}));

const { handleConfigGetHttpRequest } = await import("./config-http.js");

let sharedPort = 0;
let sharedServer: ReturnType<typeof createServer> | undefined;

beforeAll(async () => {
  sharedServer = createServer((req, res) => {
    void (async () => {
      const handled = await handleConfigGetHttpRequest(req, res, {
        auth: { mode: "token", token: TEST_GATEWAY_TOKEN, allowTailscale: false },
      });
      if (handled) {
        return;
      }
      res.statusCode = 404;
      res.end("not found");
    })().catch((err) => {
      res.statusCode = 500;
      res.end(String(err));
    });
  });

  await new Promise<void>((resolve, reject) => {
    sharedServer?.once("error", reject);
    sharedServer?.listen(0, "127.0.0.1", () => {
      const address = sharedServer?.address() as AddressInfo | null;
      sharedPort = address?.port ?? 0;
      resolve();
    });
  });
});

afterAll(async () => {
  const server = sharedServer;
  if (!server) {
    return;
  }
  await new Promise<void>((resolve) => server.close(() => resolve()));
  sharedServer = undefined;
});

beforeEach(() => {
  cfg = {};
});

const fetchConfig = async (params: { headers?: Record<string, string>; method?: string } = {}) =>
  fetch(`http://127.0.0.1:${sharedPort}/api/config`, {
    method: params.method ?? "GET",
    headers: params.headers,
  });

describe("GET /api/config", () => {
  it("returns 401 without a bearer token", async () => {
    const res = await fetchConfig();
    expect(res.status).toBe(401);
  });

  it("returns 401 with an incorrect bearer token", async () => {
    const res = await fetchConfig({ headers: { authorization: "Bearer wrong-token" } });
    expect(res.status).toBe(401);
  });

  it("returns 405 for non-GET requests", async () => {
    const res = await fetchConfig({
      method: "POST",
      headers: { authorization: `Bearer ${TEST_GATEWAY_TOKEN}` },
    });
    expect(res.status).toBe(405);
  });

  it("returns the config when authorized", async () => {
    cfg = { gateway: { trustedProxies: ["10.0.0.1"] } };
    const res = await fetchConfig({ headers: { authorization: `Bearer ${TEST_GATEWAY_TOKEN}` } });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
    expect(body.config.gateway.trustedProxies).toEqual(["10.0.0.1"]);
  });

  it("redacts sensitive fields", async () => {
    cfg = { gateway: { token: "super-secret-token" }, someProvider: { apiKey: "sk-secret" } };
    const res = await fetchConfig({ headers: { authorization: `Bearer ${TEST_GATEWAY_TOKEN}` } });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.config.gateway.token).toBe("__OPENCLAW_REDACTED__");
    expect(body.config.someProvider.apiKey).toBe("__OPENCLAW_REDACTED__");
  });
});
