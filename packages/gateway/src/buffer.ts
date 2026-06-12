import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { EvidenceInput } from '@attestor/types';
import type { EvidenceSink } from './sink.js';

/**
 * Durable local buffer for evidence recorded while the spine is unreachable.
 *
 * Records are written as JSON lines so a crash mid-write loses at most the last
 * partial line. On reconnect, `flush` replays buffered records into the sink in
 * order; if the sink fails partway, the not-yet-flushed remainder is written
 * back so nothing is lost. This is what makes T0/T1 fail-open safe: the action
 * proceeds, but its evidence is never dropped.
 */
export class EvidenceBuffer {
  constructor(private readonly path: string) {}

  /** Append one evidence record to the buffer. */
  add(input: EvidenceInput): void {
    mkdirSync(dirname(this.path), { recursive: true });
    appendFileSync(this.path, `${JSON.stringify(input)}\n`, 'utf8');
  }

  /** Buffered records, in order. */
  list(): EvidenceInput[] {
    if (!existsSync(this.path)) {
      return [];
    }
    return readFileSync(this.path, 'utf8')
      .split('\n')
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as EvidenceInput);
  }

  size(): number {
    return this.list().length;
  }

  /**
   * Replay buffered records into the sink. Returns the number flushed. If the
   * sink throws, the unflushed remainder is persisted back and the error is
   * rethrown so the caller can mark the store unhealthy again.
   */
  async flush(sink: EvidenceSink): Promise<number> {
    const pending = this.list();
    let flushed = 0;
    try {
      for (const input of pending) {
        await sink.append(input);
        flushed += 1;
      }
      this.clear();
      return flushed;
    } catch (err) {
      this.rewrite(pending.slice(flushed));
      throw err;
    }
  }

  private clear(): void {
    if (existsSync(this.path)) {
      writeFileSync(this.path, '', 'utf8');
    }
  }

  private rewrite(remaining: readonly EvidenceInput[]): void {
    const body = remaining.map((input) => JSON.stringify(input)).join('\n');
    writeFileSync(this.path, body.length > 0 ? `${body}\n` : '', 'utf8');
  }
}
