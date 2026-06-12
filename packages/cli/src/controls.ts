import { existsSync, readFileSync } from 'node:fs';

export interface ControlDefinition {
  readonly title: string;
  readonly clause: string;
  readonly summary: string;
}

export interface ControlCatalog {
  readonly framework: string;
  readonly annex: string;
  readonly controls: Readonly<Record<string, ControlDefinition>>;
}

const EMPTY: ControlCatalog = {
  framework: 'ISO/IEC 42001:2023',
  annex: 'Annex A',
  controls: {},
};

/** Load the control mapping table, tolerating its absence gracefully. */
export function loadControlCatalog(path: string): ControlCatalog {
  if (!existsSync(path)) {
    return EMPTY;
  }
  const parsed = JSON.parse(readFileSync(path, 'utf8')) as Partial<ControlCatalog>;
  return {
    framework: parsed.framework ?? EMPTY.framework,
    annex: parsed.annex ?? EMPTY.annex,
    controls: parsed.controls ?? {},
  };
}

/** Look up a control's display title, falling back to its bare id. */
export function controlTitle(catalog: ControlCatalog, id: string): string {
  const def = catalog.controls[id];
  return def ? `${id} — ${def.title}` : id;
}
