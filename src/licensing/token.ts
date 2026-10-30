export const DAY = 86_400;
export interface EntitlementClaims {
  iss: 'civoclip-license'; aud: 'civoclip-desktop'; sub: string; tier: 'pro';
  licenseType: 'lifetime' | 'perpetual_1y_updates';
  iat: number; exp: number; licenseExpiresAt: number; updatesUntil?: number; device: string;
  features: string[];
}
const verified = Symbol('verified entitlement');
export interface VerifiedEntitlement extends EntitlementClaims {
  readonly [verified]: true;
  /** Activation/verification freshness deadline; never a Pro feature deadline. */
  readonly offlineExpiresAt: number;
  readonly fresh: boolean;
}
export type PublicKeys = Readonly<Record<string, JsonWebKey>>;
// Public-only RFC 8032 fixture, deliberately unusable for production trust.
// Replace this development kid with provisioned production PUBLIC keys before release.
export const EMBEDDED_PUBLIC_KEYS: PublicKeys = Object.freeze({
  'development-fixture-only': { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo', ext: true },
});
function bytes(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid base64url');
  return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}
function json(value: string): unknown { return JSON.parse(new TextDecoder().decode(bytes(value))); }
export async function verifyEntitlement(token: string, options: {
  keys?: PublicKeys; now?: number; offlineGraceDays?: number; device?: string;
} = {}): Promise<VerifiedEntitlement> {
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const grace = options.offlineGraceDays ?? 21;
  if (!Number.isFinite(grace) || grace < 14 || grace > 30) throw new Error('Offline grace must be 14–30 days');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Malformed token');
  const [h, p, s] = parts as [string, string, string];
  const header = json(h) as Record<string, unknown>;
  if (header.alg !== 'EdDSA' || header.typ !== 'JWT' || typeof header.kid !== 'string') throw new Error('Invalid token header');
  const keys = options.keys ?? EMBEDDED_PUBLIC_KEYS;
  if (!Object.hasOwn(keys, header.kid)) throw new Error('Unknown signing key');
  const key = await crypto.subtle.importKey('jwk', keys[header.kid]!, { name: 'Ed25519' }, false, ['verify']);
  if (!await crypto.subtle.verify('Ed25519', key, bytes(s), new TextEncoder().encode(`${h}.${p}`))) throw new Error('Invalid signature');
  const c = json(p) as EntitlementClaims;
  if (c.iss !== 'civoclip-license' || c.aud !== 'civoclip-desktop' || c.tier !== 'pro' || typeof c.sub !== 'string' || !c.sub ||
      typeof c.device !== 'string' || !c.device || !Array.isArray(c.features) || !c.features.every(f => typeof f === 'string') ||
      ![c.iat,c.exp,c.licenseExpiresAt].every(Number.isSafeInteger) || c.iat > now || c.exp <= c.iat ||
      (options.device !== undefined && options.device !== c.device)) throw new Error('Invalid entitlement');
  if (c.licenseType === 'lifetime') {
    if (Object.hasOwn(c, 'updatesUntil')) throw new Error('Invalid entitlement');
  } else if (c.licenseType === 'perpetual_1y_updates') {
    if (c.updatesUntil === undefined || !Number.isSafeInteger(c.updatesUntil) || c.updatesUntil < c.iat) throw new Error('Invalid entitlement');
  } else throw new Error('Invalid entitlement');
  const offlineExpiresAt = Math.min(c.exp, c.licenseExpiresAt, c.iat + grace * DAY);
  return Object.freeze({ ...c, offlineExpiresAt, fresh: now < offlineExpiresAt, features: Object.freeze([...c.features]) as unknown as string[], [verified]: true as const });
}
export type Access = { tier: 'free'; reason: string } | { tier: 'pro'; entitlement: VerifiedEntitlement };
export async function evaluateAccess(token: string | undefined, options: Parameters<typeof verifyEntitlement>[1] = {}): Promise<Access> {
  if (!token) return { tier: 'free', reason: 'No entitlement' };
  try { return { tier: 'pro', entitlement: await verifyEntitlement(token, options) }; }
  catch { return { tier: 'free', reason: 'Entitlement unavailable or invalid; open-source features remain available' }; }
}
