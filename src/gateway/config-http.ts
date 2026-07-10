import type { IncomingMessage, ServerResponse } from "node:http";
import { loadConfig } from "../config/config.js";
import { redactConfigObject } from "../config/redact-snapshot.js";
import type { AuthRateLimiter } from "./auth-rate-limit.js";
import type { ResolvedGatewayAuth } from "./auth.js";
import { authorizeGatewayBearerRequestOrReply } from "./http-auth-helpers.js";
import { sendJson, sendMethodNotAllowed } from "./http-common.js";

/**
 * Read-only HTTP mirror of the `config.get` gateway method, for tooling that
 * wants the redacted config without speaking the WS/JSON-RPC protocol
 * (e.g. curl-based scripts, status dashboards, support bundles).
 */
export async function handleConfigGetHttpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  opts: {
    auth: ResolvedGatewayAuth;
    trustedProxies?: string[];
    rateLimiter?: AuthRateLimiter;
  },
): Promise<boolean> {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  if (url.pathname !== "/api/config") {
    return false;
  }

  if (req.method !== "GET") {
    sendMethodNotAllowed(res, "GET");
    return true;
  }

  const authorized = await authorizeGatewayBearerRequestOrReply({
    req,
    res,
    auth: opts.auth,
    trustedProxies: opts.trustedProxies,
    rateLimiter: opts.rateLimiter,
  });
  if (!authorized) {
    return true;
  }

  const cfg = loadConfig();
  sendJson(res, 200, { ok: true, config: redactConfigObject(cfg) });
  return true;
}
