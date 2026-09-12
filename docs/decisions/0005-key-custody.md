# ADR-0005 — Key custody: the KMS boundary, rotation, and revocation

**Status:** accepted and **verified against a live KMS key** · 12 September 2026
**Context:** threat T14 and SR-11. A valid EdDSA signature *is* an approval, so the tenant signing key is the highest-value asset VERA holds (asset A1 in the threat model). Until now it had no revocation path short of editing the database by hand.

## Decisions

### 1. Three key states, and the difference between the last two is the product

| State | Signs | Verifies | Meaning |
|---|---|---|---|
| `active` | yes | yes | Exactly one per tenant. |
| `retiring` | **no** | yes | Rotated away from. Tokens minted seconds before the rotation keep working until they expire. |
| `revoked` | no | **no** | Withdrawn. Every token it ever signed fails immediately. |

Rotation is routine and must never break work in flight; that is what `retiring` is for. Revocation is incident response and is deliberately abrupt: it invalidates tokens a human approved a minute ago, because a stolen key cannot be allowed a grace period.

### 2. Revoked keys are published as revoked, not dropped

The JWKS carries a `revoked` array. A receiver can then distinguish **"this key was withdrawn"** (an incident — investigate what was signed with it) from **"I have never heard of this key"** (probably a stale JWKS cache). Silently omitting the key would collapse those two very different situations into one.

### 3. Revoking the active key mints a replacement in the same transaction

The alternative — refusing to revoke without first rotating — would mean the fastest response to a stolen key is unavailable exactly when it is needed. A tenant that cannot sign cannot decide, so the replacement is not optional.

### 4. Every signature is audited 1:1 with a token (SR-11)

`token.issued` is written for each signature, carrying `jti` and `kid`. `GET /v1/keys` reports parity between `decision_tokens` rows and those events. A gap means either something signed outside the decision path — what a stolen key looks like from the outside — or an audit write was lost. Both warrant distrusting every token from that tenant until explained.

### 5. Key management requires the `admin` role

Reviewers approve actions; owners manage keys. Revocation invalidates other people's live approvals, which is not a reviewer's decision to make.

### 6. The KMS boundary is the `Signer` interface

```ts
export interface Signer {
  readonly kid: string;
  signCompact(header: JwsHeader, payload: Record<string, unknown>): Promise<string>;
}
```

The interface takes a header and payload rather than a configured `SignJWT`, because a remote signer can only be handed bytes. That shape change was the whole cost of supporting KMS; no caller changed.

Two implementations, and the difference between them is the point:

| | `localSigner` (development) | `kmsSigner` (production) |
|---|---|---|
| Private key | AES-GCM sealed in our database, unsealed into process memory | In KMS; never reaches this process |
| Export path | `exportPrivateJwk` exists in code | None — `@vera/signer-kms` exposes only `kmsSigner`, `kmsPublicJwk`, `kidForKeyArn`, and a test asserts that list |
| Compromise of DB + `VERA_MASTER_KEY` | Yields a usable signing key | Yields nothing signable |

AWS KMS gained EdDSA (`ECC_NIST_EDWARDS25519`) in November 2025, which is what makes this a drop-in: the token format stays Ed25519 and **no verifier changes**. Had that not existed we would have faced a much worse choice — switch every token to ECDSA, or keep keys in our own custody.

Three deliberate refusals in the implementation:

1. **A 64-byte signature guard.** KMS DER-wraps ECDSA signatures; JWS EdDSA requires the bare 64 bytes. Passing a wrapped signature through would mint tokens that fail verification *everywhere* — a system-wide outage presenting as a mystery. The signer throws instead, naming the likely cause.
2. **No fallback to a local key.** A key row with a `kms_key_arn` signs through KMS or not at all. Falling back would silently downgrade the custody a tenant was promised (T14) — and the tokens would fail verification anyway, so the fallback buys nothing even on its own terms.
3. **No fallback to ambient AWS credentials.** Deployments routinely carry broad `AWS_*` credentials for unrelated services. Inheriting them would mean VERA signs under whatever identity was lying around. Credentials are `VERA_KMS_*`, and using an instance role is an explicit opt-in.

Custody is a schema invariant, not a convention: `signing_keys` carries a `CHECK` that exactly one of `private_jwk_sealed` and `kms_key_arn` is set. Neither would fail at the moment someone needed to sign; both would silently pick one.

### 7. Adopting a KMS key is a rotation

`vera-api register-kms-key --org-id <id> --arn <arn>` fetches the public half **first** — proving the key exists, carries the right spec, and is reachable with these credentials — and only then makes it active, moving the outgoing local key to `retiring`. Registering first and discovering otherwise at signing time would take the tenant offline. The old key keeps verifying tokens already in flight; revoking it stays a separate, deliberate act.

## Consequences

- Accepted risk #8 (development-grade key custody) is **closed for tenants registered against a KMS key**, and remains open for any tenant still on `localSigner`. Custody is now per-key, so this is a statement about rows, not about the deployment.
- Rotation is safe to do routinely and should be scheduled once there is anything to schedule it with.
- Revocation is loud by design: the response reports exactly how many tokens it invalidated.
- The parity check is a cheap tripwire for the most serious failure mode this system has.
- **The live run has now happened** (12 September 2026, `apps/api/scripts/kms-smoke.mjs`). Every assumption that only AWS could settle held:
  - `GetPublicKey` returns an `ECC_NIST_EDWARDS25519` key that converts to a usable `OKP/Ed25519` JWK.
  - `ED25519_SHA_512` over a `RAW` message returns a **bare 64-byte signature**, not a DER-wrapped one. This was the assumption worth testing: a wrapped signature would have produced tokens that fail verification everywhere, presenting as a system-wide mystery rather than an error. The guard would have caught it; it did not need to.
  - The IAM identity's three permissions are sufficient and nothing broader is required.
  - A token refuses to verify against a changed command.
- End to end on a real tenant: `register-kms-key` rotated `LogaXP Demo` onto the KMS key (the local key moved to `retiring`, so tokens already issued kept verifying), a `POST /v1/decide` returned a token stamped `kid: kms_2bae56fd…`, and that token verified offline against the tenant's published JWKS. `doctor` reports the custody as KMS.
