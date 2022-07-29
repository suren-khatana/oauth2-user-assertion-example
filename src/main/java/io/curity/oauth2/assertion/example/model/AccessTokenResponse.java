/**
 * Simple POJO to model access tokens returned by Curity server
 *
 * @author Surendra Khatana
 * @version 1.0
 * @since 2022-07-28
 */
package io.curity.oauth2.assertion.example.model;


import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
public class AccessTokenResponse {
    @JsonProperty("access_token")
    private String accessToken;
    @JsonProperty("token_type")
    private String tokenType;
    @JsonProperty("expires_in")
    private int expiresIn;
}
