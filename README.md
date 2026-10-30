# Civoclip core
Apache-2.0 open-source skeleton for cross-language highlight clipping and localization.
Civoclip website: https://clip.eascivo.com.

Node 22: `npm install && npm test && npm run build`. No media engine is bundled;
typed ingest, transcribe, translate, highlight-detect and clip/export stubs throw
`PipelineNotImplemented`. These OSS stages never consult licensing.

`HttpLicenseClient` calls provider-independent `/api/license/activate`, `/refresh`
and `/deactivate`. A successful activation is checked with Ed25519 and a `kid`
public-key map before being cached in memory. Supply production public keys at
packaging time; the embedded development fixture is PUBLIC ONLY, must be removed
before release, and is not a production trust anchor. Tests generate fresh keypairs.
The server's raw private key is never part of this repository.

Every token requires a signed `updatesUntil` claim (Unix seconds, safe integer,
at least `iat`). Pro builds released on or before that date remain usable forever;
license expiry only stops updates. The Pro package checks the build's fixed release
date against `updatesUntil`, independently of the current clock.

`offlineExpiresAt` is the earliest of token `exp`, `licenseExpiresAt`, or `iat` plus
`offlineGraceDays` (21 by default, configurable 14–30). It only controls freshness:
`entitlement.fresh` is false at or after this deadline, indicating a refresh is
needed. Signature-valid cached tokens still yield Pro access for eligible builds.
Activation/refresh responses must be fresh before replacing the cache. Missing
tokens/keys, invalid signatures, wrong issuer/audience/device, or malformed claims
yield free access; OSS is never blocked.
Network errors preserve a previously valid cache; server 401/403/404 clears it.
Offline revocation takes effect when a server response clears the cache.
A host desktop app must securely persist tokens and prevent local clock rollback;
this skeleton intentionally provides no UI, disk storage or anti-tamper guarantees.

The legacy `CLIP-` prefix is retained after the product rename.
License format: `CLIP-XXXX-XXXX-XXXX-XXXX`, uppercase RFC4648 base32 (80 random bits).
Pro lives separately in `../civoclip-pro`; web/commerce code in `../civoclip-website`.
See CONTRIBUTING.md for DCO and TRADEMARK.md for name/logo restrictions.
