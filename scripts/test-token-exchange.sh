#!/usr/bin/env bash
# End-to-end token exchange test against a locally running tokendings.
#
# Prereqs (already covered by `mise run local`):
#   - tokendings on :8080 (with local.env)
#   - mock-oauth2-server on :7070
#   - postgres on :5432
#
# This script:
#   1. Generates a keypair for "consumer" and "target"
#   2. Mints a registration bearer token from mock-oauth2-server (registration-idp, aud=bogus)
#   3. Signs a software statement with the local jwker-jwks key
#   4. Registers both clients via /registration/client
#   5. Mints a subject_token from mock-oauth2-server (subject-idp)
#   6. Signs a client_assertion with the consumer's private key
#   7. Performs the token exchange against /token

set -euo pipefail

TOKENDINGS_URL="${TOKENDINGS_URL:-http://localhost:8080}"
TOKENDINGS_ISSUER="${TOKENDINGS_ISSUER:-http://tokendings}"
MOCK_URL="${MOCK_URL:-http://localhost:7070}"
JWKER_JWK_FILE="${JWKER_JWK_FILE:-src/test/resources/jwker-jwks.json}"

WORK_DIR="$(mktemp -d -t tokendings-XXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

CONSUMER_APP_ID="dev:team:consumer"
TARGET_APP_ID="dev:team:target"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

# ----------------------------------------------------------------------------
# 0. Tooling sanity check
# ----------------------------------------------------------------------------
for cmd in step jq curl; do
    command -v "$cmd" >/dev/null || { echo "missing: $cmd"; exit 1; }
done

# ----------------------------------------------------------------------------
# 1. Generate keypairs (one per client)
# ----------------------------------------------------------------------------
log "Generating consumer + target keypairs"
gen_jwk() {
    local name="$1"
    step crypto jwk create \
        "$WORK_DIR/${name}-pub.jwk" "$WORK_DIR/${name}-priv.jwk" \
        --kty RSA --size 2048 --use sig --alg RS256 \
        --kid "${name}-kid" --no-password --insecure --force >/dev/null
}
gen_jwk consumer
gen_jwk target

consumer_jwks_json=$(jq -c '{keys: [.]}' "$WORK_DIR/consumer-pub.jwk")
target_jwks_json=$(jq -c '{keys: [.]}' "$WORK_DIR/target-pub.jwk")

# ----------------------------------------------------------------------------
# 2. Get registration bearer token from mock-oauth2-server (aud=bogus)
# ----------------------------------------------------------------------------
log "Requesting registration bearer token (issuer=registration-idp, aud=bogus)"
REG_TOKEN=$(curl -sS -X POST "${MOCK_URL}/registration-idp/token" \
    -d 'grant_type=client_credentials' \
    -d 'client_id=jwker' \
    -d 'client_secret=ignored' \
    -d 'scope=bogus' \
    | jq -r .access_token)

[ -n "$REG_TOKEN" ] && [ "$REG_TOKEN" != "null" ] || { echo "no registration token"; exit 1; }

# ----------------------------------------------------------------------------
# 3. Sign software statements with the local jwker JWK
# ----------------------------------------------------------------------------
sign_software_statement() {
    local app_id="$1"
    local inbound="$2"     # JSON array as string
    local outbound="$3"    # JSON array as string
    jq -n \
        --arg appId "$app_id" \
        --argjson in "$inbound" \
        --argjson out "$outbound" \
        '{appId: $appId, accessPolicyInbound: $in, accessPolicyOutbound: $out}' \
        | step crypto jwt sign --key "$JWKER_KEY" --alg RS256 --subtle
}

log "Signing software statements"
JWKER_KEY="$WORK_DIR/jwker.jwk"
jq '.keys[0]' "$JWKER_JWK_FILE" > "$JWKER_KEY"
CONSUMER_SS=$(sign_software_statement "$CONSUMER_APP_ID" '[]' "[\"$TARGET_APP_ID\"]")
TARGET_SS=$(sign_software_statement   "$TARGET_APP_ID"   "[\"$CONSUMER_APP_ID\"]" '[]')

# ----------------------------------------------------------------------------
# 4. Register both clients
# ----------------------------------------------------------------------------
register_client() {
    local name="$1"; local jwks_json="$2"; local ss="$3"
    jq -n \
        --arg client_name "$name" \
        --argjson jwks "$jwks_json" \
        --arg software_statement "$ss" \
        '{client_name: $client_name, jwks: $jwks, software_statement: $software_statement, scopes: [], grant_types: []}' \
        | curl -sS -X POST "${TOKENDINGS_URL}/registration/client" \
            -H "Authorization: Bearer ${REG_TOKEN}" \
            -H 'Content-Type: application/json' \
            --data-binary @-
}

log "Registering consumer ($CONSUMER_APP_ID)"
CONSUMER_REG=$(register_client "$CONSUMER_APP_ID" "$consumer_jwks_json" "$CONSUMER_SS")
echo "$CONSUMER_REG" | jq -c '{client_id, jwks: (.jwks.keys | map(.kid))}' || { echo "$CONSUMER_REG"; exit 1; }

log "Registering target ($TARGET_APP_ID)"
TARGET_REG=$(register_client "$TARGET_APP_ID" "$target_jwks_json" "$TARGET_SS")
echo "$TARGET_REG" | jq -c '{client_id, jwks: (.jwks.keys | map(.kid))}' || { echo "$TARGET_REG"; exit 1; }

# ----------------------------------------------------------------------------
# 5. Get a subject_token from mock-oauth2-server (subject-idp)
# ----------------------------------------------------------------------------
log "Requesting subject_token (issuer=subject-idp)"
SUBJECT_TOKEN=$(curl -sS -X POST "${MOCK_URL}/subject-idp/token" \
    -d 'grant_type=client_credentials' \
    -d 'client_id=enduser' \
    -d 'client_secret=ignored' \
    -d 'scope=anything' \
    | jq -r .access_token)

[ -n "$SUBJECT_TOKEN" ] && [ "$SUBJECT_TOKEN" != "null" ] || { echo "no subject token"; exit 1; }

# ----------------------------------------------------------------------------
# 6. Sign client_assertion with consumer's private key
#    iss = sub = clientId, aud = token endpoint
# ----------------------------------------------------------------------------
log "Signing client_assertion (iss=sub=$CONSUMER_APP_ID, aud=$TOKENDINGS_ISSUER/token)"
CLIENT_ASSERTION=$(jq -n '{}' | step crypto jwt sign \
    --key "$WORK_DIR/consumer-priv.jwk" \
    --alg RS256 \
    --iss "$CONSUMER_APP_ID" \
    --sub "$CONSUMER_APP_ID" \
    --aud "${TOKENDINGS_ISSUER}/token" \
    --exp "$(($(date +%s) + 120))")

# ----------------------------------------------------------------------------
# 7. Token exchange
# ----------------------------------------------------------------------------
log "POST ${TOKENDINGS_URL}/token (token exchange)"
RESPONSE=$(curl -sS -X POST "${TOKENDINGS_URL}/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
    --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    --data-urlencode "client_assertion=${CLIENT_ASSERTION}" \
    --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
    --data-urlencode "subject_token=${SUBJECT_TOKEN}" \
    --data-urlencode "audience=${TARGET_APP_ID}")

echo
echo "$RESPONSE" | jq .

ACCESS_TOKEN=$(echo "$RESPONSE" | jq -r '.access_token // empty')
if [ -n "$ACCESS_TOKEN" ]; then
    log "Decoded exchanged token claims:"
    step crypto jwt inspect --insecure <<< "$ACCESS_TOKEN" | jq .payload
else
    log "Token exchange failed"
    exit 1
fi
