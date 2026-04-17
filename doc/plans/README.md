# Plans

Numbered prefixes are for ordering and stable references, not strict dependencies.
Each plan has a single thesis; see one-liners below.

## Index

- **[01 — Token exchange OIDC federation](./01-token-exchange-oidc-federation.md)**
  Ship federated client authentication for `/token` (external OIDC issuers as
  `client_assertion` signers). Happy path implemented; remaining work closes
  registrar-side trust-boundary gaps, adds negative tests, startup validation,
  observability, and docs.

- **[02 — Auth infra unification](./02-auth-infra-unification.md)**
  Collapse three parallel JWKS stacks (auth0 for bearer auth, Nimbus for token
  validation, Nimbus for federated client auth) onto a single Nimbus-based
  `IssuerJwks` with per-issuer dedup and fail-fast boot-time JWKS warm-up.

- **[03 — Token exchange API simplification](./03-token-exchange-api-simplification.md)**
  Delete the vestigial `TokenRequestContext.From` DSL and route `/token` through
  a plain `ClientAuthenticator` service, mirroring `ClientRegistrationApi`.

## Recommended execution order

The plans are independently valuable and can land in any order, but some
orderings avoid rework:

1. **01 first** (already in progress). Independent of 02/03.
2. **02 before 03.** Plan 03 reads `FederatedIssuer`; plan 02 reshapes it.
   Doing 03 first means migrating the new `ClientAuthenticator` again when 02
   lands. Doing 02 first means 03 picks up the stable shape directly.
3. **03 last.** Pure simplification; benefits from 02's cleaner seams.

If 03 must land before 02 for unrelated reasons, budget a test-rewrite:
`ClientAuthenticator` and its unit tests will migrate through two shapes of
`FederatedIssuer` (pre- and post-02). Do it only if 02 is blocked.

## Conventions

- One thesis per plan. Resist merging.
- Non-goals are load-bearing — they document rejected alternatives so future
  readers don't re-litigate.
- "Out of scope — separate follow-ups" sections cross-link sibling plans.
