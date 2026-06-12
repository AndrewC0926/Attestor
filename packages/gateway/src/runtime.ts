import { Spine, resolveKeyPair, type StoreConfig } from '@attestor/spine';
import { GatewayCore } from './core.js';
import { EvidenceBuffer } from './buffer.js';
import { SpineEvidenceSink } from './sink.js';
import { PolicyV0Engine } from './policy/engine.js';
import { connectDownstream, type DownstreamConfig } from './downstream.js';
import {
  buildAuditedServer,
  serveHttp,
  serveStdio,
  type HttpServeOptions,
} from './server.js';

/** Everything needed to stand up a gateway in front of a downstream MCP server. */
export interface GatewayConfig {
  readonly agentId: string;
  readonly policyPath: string;
  readonly store: StoreConfig;
  readonly keyFilePath: string;
  readonly bufferPath: string;
  readonly downstream: DownstreamConfig;
  readonly transports: {
    readonly stdio?: boolean;
    readonly http?: HttpServeOptions;
  };
  readonly checkpointInterval?: number;
}

export interface GatewayHandle {
  readonly core: GatewayCore;
  readonly spine: Spine;
  stop(): Promise<void>;
}

/**
 * Assemble and start a gateway: open the spine, compile policy v0, wire the
 * audit core, connect downstream, and serve on the configured transports.
 */
export async function startGateway(config: GatewayConfig): Promise<GatewayHandle> {
  const keys = resolveKeyPair(config.keyFilePath);
  const spine = await Spine.open(config.store, keys, {
    ...(config.checkpointInterval !== undefined
      ? { checkpointInterval: config.checkpointInterval }
      : {}),
  });
  const engine = PolicyV0Engine.fromFile(config.policyPath);
  const core = new GatewayCore(
    engine,
    new SpineEvidenceSink(spine),
    new EvidenceBuffer(config.bufferPath),
  );

  const downstream = await connectDownstream(config.downstream);

  // An MCP Server binds to a single transport, so we build one audited server
  // per enabled transport; they share the same audit core and downstream client.
  const stoppers: Array<() => Promise<void>> = [];
  if (config.transports.stdio) {
    const server = buildAuditedServer(core, downstream, { agentId: config.agentId });
    await serveStdio(server);
    stoppers.push(() => server.close());
  }
  if (config.transports.http) {
    const server = buildAuditedServer(core, downstream, { agentId: config.agentId });
    const stopHttp = await serveHttp(server, config.transports.http);
    stoppers.push(stopHttp);
    stoppers.push(() => server.close());
  }

  return {
    core,
    spine,
    async stop(): Promise<void> {
      for (const stopFn of stoppers) {
        await stopFn();
      }
      await downstream.close();
      await spine.close();
    },
  };
}
