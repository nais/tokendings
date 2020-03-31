package io.nais.security.oauth2

import com.nimbusds.jwt.JWTClaimsSet
import org.junit.jupiter.api.Test
import java.time.Instant
import java.util.Date

internal class ClientRegistryTest {

    /**
     * https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication - private_key_jwt
     */
    @Test
    fun `client assertion for private_key_jwt should contain required claims`() {
        // TODO - should we allow for reuse of token? -
        //  ref. REQUIRED. JWT ID. A unique identifier for the token, which can be used to prevent reuse of the token.
        //  These tokens MUST only be used once, unless conditions for reuse were negotiated between the parties;
        //  any such negotiation is beyond the scope of this specification.
        JWTClaimsSet.Builder()
            .issuer("client_id_1")
            .subject("client_id_1")
            .audience("https://oauth2-server-tokenendpoint/token")
            .jwtID("notusedbefore")
            .issueTime(Date.from(Instant.now()))
            .expirationTime(Date.from(Instant.now().plusSeconds(60)))
    }
}
/*
*
* iss
REQUIRED. Issuer. This MUST contain the client_id of the OAuth Client.
sub
REQUIRED. Subject. This MUST contain the client_id of the OAuth Client.
aud
REQUIRED. Audience. The aud (audience) Claim. Value that identifies the Authorization Server as an intended audience. The Authorization Server MUST verify that it is an intended audience for the token. The Audience SHOULD be the URL of the Authorization Server's Token Endpoint.
jti
REQUIRED. JWT ID. A unique identifier for the token, which can be used to prevent reuse of the token. These tokens MUST only be used once, unless conditions for reuse were negotiated between the parties; any such negotiation is beyond the scope of this specification.
exp
REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for processing.
iat
OPTIONAL. Time at which the JWT was issued.
*
* */
