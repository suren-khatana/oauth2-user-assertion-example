/**
 * Entry point
 *
 * @author Surendra Khatana
 * @version 1.0
 * @since 2022-07-28
 */

package io.curity.oauth2.assertion.example;

import io.curity.oauth2.assertion.example.client.OAuthClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Oauth2UserAssertionExampleApplication implements CommandLineRunner {
	private static final Logger logger = LoggerFactory.getLogger(Oauth2UserAssertionExampleApplication.class);
	private final OAuthClient client;

	public Oauth2UserAssertionExampleApplication(OAuthClient client) {
		this.client = client;
	}

	public static void main(String[] args) {
		SpringApplication.run(Oauth2UserAssertionExampleApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		logger.info("**** Starting the JWT assertion based User authentication ****");
		logger.info("Token from Curity server: {}", client.getAccessToken());
	}
}
