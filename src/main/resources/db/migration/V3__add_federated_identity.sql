-- Add columns to support federated OIDC client authentication.
-- The pair (federated_issuer, federated_subject) uniquely identifies a client
-- when present. Both columns are nullable; legacy clients authenticate via
-- their registered JWKS (stored in the `data` JSONB blob) and leave these null.
ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS federated_issuer  TEXT,
    ADD COLUMN IF NOT EXISTS federated_subject TEXT;

-- Partial unique index enforces uniqueness only when a federated identity is
-- actually set, so multiple legacy (null, null) rows remain allowed.
CREATE UNIQUE INDEX IF NOT EXISTS clients_federated_identity_uidx
    ON clients (federated_issuer, federated_subject)
    WHERE federated_issuer IS NOT NULL
      AND federated_subject IS NOT NULL;
