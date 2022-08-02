/**
 * This is a utility class providing helper methods to create,sign & verify jason web tokens
 *
 * @author Surendra Khatana
 * @version 1.0
 * @since 2022-07-28
 */

package io.curity.oauth2.assertion.example.utils;

import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.rsa.RSASigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.UUID;

@Component
public class JWSUtil {
    private static final Logger logger = LoggerFactory.getLogger(JWSUtil.class);
    private KeyUtil keyUtil;

    public JWSUtil(KeyUtil keyUtil) {
        this.keyUtil = keyUtil;
    }


    /**
     * This method is used to create a user assertion JWS as per https://datatracker.ietf.org/doc/html/rfc7523#section-3
     *
     * @return a signed jason web token.
     */
    public String generateUserAssertionJWS(String clientId, String audience) throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException,
            NoSuchAlgorithmException {
        // Create a signer using the custom RSA private key
        Signer signer = RSASigner.newSHA256Signer(keyUtil.getPrivateKey());

        // Create a new JWT as per the specification https://datatracker.ietf.org/doc/html/rfc7523#section-3
        JWT jwt = new JWT()
                .setIssuer(clientId)
                .setIssuedAt(ZonedDateTime.now(ZoneOffset.UTC))
                .setSubject("suren") // username
                .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(5)).setUniqueId(UUID.randomUUID().toString())
                .setNotBefore(ZonedDateTime.now(ZoneOffset.UTC))
                .setAudience(audience)
                .addClaim("my_claim", "my_value");  // custom data to be extracted in the token procedure and added to access token as claims.

        // Sign and encode the JWT
        String jws = JWT.getEncoder().encode(jwt, signer);
        logger.info("User assertion JWT sent to the Server for user authentication: {}", jws);
        return jws;
    }

    public String generateClientAssertionJWS(String clientId, String audience) throws UnrecoverableKeyException, CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException {
        // Create a signer using the custom RSA private key
        Signer signer = RSASigner.newSHA256Signer(keyUtil.getPrivateKey());

        // Create a new JWT as per the specification https://datatracker.ietf.org/doc/html/rfc7523#section-2.2
        JWT jwt = new JWT()
                .setIssuer(clientId)
                .setIssuedAt(ZonedDateTime.now(ZoneOffset.UTC))
                .setSubject(clientId)
                .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(5)).setUniqueId(UUID.randomUUID().toString())
                .setNotBefore(ZonedDateTime.now(ZoneOffset.UTC))
                .setAudience(audience);

        // Sign and encode the JWT
        String jws = JWT.getEncoder().encode(jwt, signer);
        logger.info("Client assertion JWT sent to the Server for client authentication: {}", jws);
        return jws;
    }

}
