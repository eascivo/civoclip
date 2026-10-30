# Civoclip local verification

Verified: 2026-10-30 20:39:14 北京时间. Platform: macOS arm64, Node 22.23.3, npm 10.9.9.

- `npm install --no-fund --no-audit`: exit 0.
- `npm test`: exit 0; 1 test file(s), 25 tests passed, 0 failed/skipped.
- `npm run build`: exit 0.

Rename evidence: `../evidence/rename-20261030/` (outside the repositories), with
command logs and `results.json`. Original pre-rename evidence remains in
`../evidence/`; earlier verification is also preserved in each repository's history.

`CLIP-` license keys remain unchanged. Token issuer/audience were renamed together
to `civoclip-license` / `civoclip-desktop` in the server and clients; old development
tokens require reactivation. No production license/token migration was performed.
