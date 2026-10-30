import { evaluateAccess, type Access, type PublicKeys } from './token.js';
export const LICENSE_KEY_PATTERN = /^CLIP-(?:[A-Z2-7]{4}-){3}[A-Z2-7]{4}$/;
export function isLicenseKey(value: string): boolean { return value.length === 24 && LICENSE_KEY_PATTERN.test(value); }
export interface Device { device_fingerprint: string; device_name?: string; app_version: string }
export interface LicenseClient {
  activate(key: string, device: Device): Promise<string>;
  refresh(key: string, device: Device): Promise<string>;
  deactivate(key: string, device: Device): Promise<void>;
  access(deviceHash?: string): Promise<Access>;
}
export class HttpLicenseClient implements LicenseClient {
  private token?: string;
  private readonly base: URL;
  constructor(baseUrl: string, private readonly options: { fetch?: typeof fetch; keys?: PublicKeys; offlineGraceDays?: number; now?: () => number } = {}) {
    this.base = new URL(baseUrl);
    if (this.base.protocol !== 'https:' && !(this.base.protocol === 'http:' && ['localhost','127.0.0.1','[::1]'].includes(this.base.hostname))) throw new Error('HTTPS required');
    if (options.offlineGraceDays !== undefined && (!Number.isFinite(options.offlineGraceDays) || options.offlineGraceDays < 14 || options.offlineGraceDays > 30)) throw new Error('Offline grace must be 14–30 days');
  }
  private async request(action: string, key: string, device: Device): Promise<Record<string, unknown>> {
    if (!isLicenseKey(key)) throw new Error('Expected CLIP-XXXX-XXXX-XXXX-XXXX using base32 characters');
    const response = await (this.options.fetch ?? fetch)(new URL(`/api/license/${action}`, this.base), {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key, ...device }),
    });
    if (!response.ok) {
      if ([401,403,404].includes(response.status)) this.token = undefined;
      throw new Error(`License ${action} failed (${response.status})`);
    }
    return await response.json() as Record<string, unknown>;
  }
  private async obtain(action: string, key: string, device: Device): Promise<string> {
    const result = await this.request(action, key, device);
    if (typeof result.token !== 'string') throw new Error('Missing entitlement token');
    const access = await evaluateAccess(result.token, { keys: this.options.keys, offlineGraceDays: this.options.offlineGraceDays, now: this.options.now?.(), device: await deviceHash(device.device_fingerprint) });
    if (access.tier !== 'pro') throw new Error('Server returned an invalid entitlement');
    if (!access.entitlement.fresh) throw new Error('Server returned a stale entitlement');
    this.token = result.token;
    return result.token;
  }
  activate(key: string, device: Device) { return this.obtain('activate', key, device); }
  refresh(key: string, device: Device) { return this.obtain('refresh', key, device); }
  async deactivate(key: string, device: Device): Promise<void> { await this.request('deactivate', key, device); this.token = undefined; }
  access(device?: string): Promise<Access> { return evaluateAccess(this.token, { keys: this.options.keys, offlineGraceDays: this.options.offlineGraceDays, now: this.options.now?.(), device }); }
}
export async function deviceHash(fingerprint: string): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(fingerprint))), n => n.toString(16).padStart(2,'0')).join('');
}
