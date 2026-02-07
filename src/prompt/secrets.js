import { randomUUID } from 'node:crypto';

const SECRET_HANDLE_PREFIX = 'secret:';
const SECRET_HANDLE_RE = /^secret:[0-9a-fA-F-]{10,}$/;

export function isSecretHandle(value) {
  if (typeof value !== 'string') return false;
  return SECRET_HANDLE_RE.test(value.trim());
}

export class SecretStore {
  constructor() {
    this._map = new Map(); // id -> { value, meta }
  }

  put(value, meta = null) {
    const id = randomUUID();
    this._map.set(id, { value, meta });
    return `${SECRET_HANDLE_PREFIX}${id}`;
  }

  get(handle) {
    const h = String(handle || '').trim();
    if (!isSecretHandle(h)) return null;
    const id = h.slice(SECRET_HANDLE_PREFIX.length);
    const entry = this._map.get(id);
    return entry ? entry.value : null;
  }

  require(handle, { label = 'secret handle' } = {}) {
    const v = this.get(handle);
    if (v === null || v === undefined) throw new Error(`Unknown ${label}: ${String(handle || '').trim()}`);
    return v;
  }
}

