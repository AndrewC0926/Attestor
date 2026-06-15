/**
 * @attestor/proxy — the real-traffic interception core.
 *
 * A real MCP proxy server that an agent connects to; it classifies every tool
 * call with the gateway's policy engine, records evidence to the spine in the
 * hot path (record-before-forward for T2/T3), and only forwards allowed calls
 * to the real downstream MCP tools. Strictly additive: it reuses the gateway's
 * decision logic and the spine's recording — it never modifies either.
 */
export {
  ProxyCore,
  type ProxyCall,
  type Forward,
  type ProxyOutcome,
  type ProxyError,
  type ProxyErrorCode,
  type ProxyCoreOptions,
} from './proxy-core.js';
export { buildProxyServer, type ProxyServerOptions } from './server.js';
export { serveProxyHttp, type ProxyHttpOptions, type ProxyHttpHandle } from './http.js';
