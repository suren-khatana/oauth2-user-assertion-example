/**
 * This class orchestrates the user authentication flow using JWT assertion.
 *
 * @author Surendra Khatana
 * @version 1.0
 * @since 2022-07-28
 */

package io.curity.oauth2.assertion.example.client;

import io.curity.oauth2.assertion.example.model.AccessTokenResponse;
import io.curity.oauth2.assertion.example.utils.JWSUtil;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Map;
import java.util.Optional;

@Component
public class OAuthClient {
    private final JWSUtil jwsUtil;
    private final RestTemplate restTemplate;
    @Value("${io.curity.oauth2.issuer}")
    private String issuer;
    @Value("${io.curity.oauth2.clientId}")
    private String clientId;

    @Value("${io.curity.oauth2.clientSecret}")
    private String clientSecret;
    @Value("${io.curity.oauth2.grant-type}")
    private String grantType;

    @Value("${io.curity.oauth2.client-assertion-type}")
    private String clientAssertionType;

    @Autowired
    public OAuthClient(RestTemplateBuilder restTemplateBuilder, JWSUtil jwsUtil) {
        this.restTemplate = restTemplateBuilder.build();
        this.jwsUtil = jwsUtil;
    }

    /**
     * This method is used to get the token endpoint url.
     *
     * @return token endpoint url fetched from the oidc metadata
     */
    private String getTokenEndPoint() {
        Map<String, Object> jsonResponse = restTemplate.getForObject(issuer.concat("/.well-known/openid-configuration"), Map.class);
        Optional.ofNullable(jsonResponse).orElseThrow(() -> (new IllegalStateException("OIDC metadata endpoint json is empty")));

        Optional<Object> tokenEndpoint = jsonResponse.entrySet().stream().filter(e -> "token_endpoint".equalsIgnoreCase(e.getKey())).map(Map.Entry::getValue).findFirst();
        return (String) tokenEndpoint.orElseThrow(() -> new IllegalStateException("token_endpoint is not found in the OIDC metadata response"));
    }

    /**
     * This method fetches the access token from curity server using JWT assertion for user authentication.
     *
     * @return an access token response issued by Curity server {@link AccessTokenResponse}
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7523#section-2.2">rfc7523</a>
     */
    public AccessTokenResponse getAccessToken() throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-type", "application/x-www-form-urlencoded");
        MultiValueMap<String, String> reqBody = new LinkedMultiValueMap<>();
        reqBody.add("scope","email");
        reqBody.add("assertion", jwsUtil.generateUserAssertionJWS(this.clientId, this.issuer)); // for user authentication
        reqBody.add("grant_type", this.grantType);
        reqBody.add("client_assertion_type", this.clientAssertionType );
        reqBody.add("client_assertion", jwsUtil.generateClientAssertionJWS(this.clientId, this.issuer)); // for client authentication
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(reqBody, headers);
        ResponseEntity<AccessTokenResponse> response = restTemplate.postForEntity(getTokenEndPoint(), request, AccessTokenResponse.class);
        return response.getBody();
    }
}
