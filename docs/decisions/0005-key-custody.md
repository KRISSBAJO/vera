# ADR-0005 — Key custody: the KMS boundary, rotation, and revocation

**Status:** accepted (rotation and revocation implemented; KMS backend pending credentials) · 12 September 2026
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

### 6. The KMS boundary is the `Signer` interface — and it is honestly not yet a KMS

```ts
export interface Signer {
  readonly kid: string;
  sign(jwt: SignJWT): Promise<string>;
}
```

Nothing outside `packages/decision-token` and `apps/api/src/services.ts` touches private key material. Today the only implementation is `localSigner`, which unseals an AES-GCM-wrapped JWK from the database using `VERA_MASTER_KEY`. **That is development-grade custody, not production custody**, and the difference should not be glossed:

- an operator with database access *and* the master key can extract a private key;
- `exportPrivateJwk` exists, so an export path exists in code (KMS's central virtue is that it does not).

A `kmsSigner` implementing the same interface — where `sign()` is an API call and the key never leaves the HSM — is a drop-in replacement, and the rest of the system needs no change. It is not written yet because it needs cloud credentials and would be untestable here without them. **Until it exists, VERA should not hold keys for anyone else's production traffic.** This is recorded as an accepted risk rather than presented as complete.

## Consequences

- Rotation is safe to do routinely and should be scheduled once there is anything to schedule it with.
- Revocation is loud by design: the response reports exactly how many tokens it invalidated.
- The parity check is a cheap tripwire for the most serious failure mode this system has.
- `docs/threat-model.md` §5 gains an accepted risk: production key custody is pending the KMS signer.
