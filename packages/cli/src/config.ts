import { Spine, resolveKeyPair, storeConfigFromEnv, type StoreConfig } from '@attestor/spine';

/** Resolved CLI configuration, sourced from environment with sane local defaults. */
export interface CliConfig {
  readonly store: StoreConfig;
  readonly keyFilePath: string;
  readonly policyPath: string;
  readonly controlsPath: string;
  readonly bufferPath: string;
}

export function resolveConfig(env: NodeJS.ProcessEnv = process.env): CliConfig {
  return {
    store: storeConfigFromEnv(env),
    keyFilePath: env.ATTESTOR_KEY_FILE ?? '.attestor/signing-key.json',
    policyPath: env.ATTESTOR_POLICY_FILE ?? 'policies/v0.yaml',
    controlsPath: env.ATTESTOR_CONTROLS_FILE ?? 'data/iso42001-controls.json',
    bufferPath: env.ATTESTOR_BUFFER_FILE ?? '.attestor/buffer.jsonl',
  };
}

/** Open a Spine from resolved config (used by verify and attest). */
export function openSpine(config: CliConfig): Promise<Spine> {
  return Spine.open(config.store, resolveKeyPair(config.keyFilePath));
}
