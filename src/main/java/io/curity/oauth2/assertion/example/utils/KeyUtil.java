/**
 * This is a utility class providing helper methods to read private key & public key from a keystore.
 *
 * @author Surendra Khatana
 * @version 1.0
 * @since 2022-07-28
 */


package io.curity.oauth2.assertion.example.utils;



import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


@Component
public class KeyUtil {
    @Value("${io.curity.oauth2.jwt.keystore-path}")
    private String keyStorePath;
    @Value("${io.curity.oauth2.jwt.keystore-password}")
    private String keyStorePassword;

    @Value("${io.curity.oauth2.jwt.key-alias}")
    private String keyAlias;

    /**
     * This method reads a .p12 file in to java security keystore object
     *
     * @return a java security keystore {@link java.security.KeyStore}
     */
    private KeyStore readKeystore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream(this.keyStorePath), this.keyStorePassword.toCharArray());
        return keystore;
    }

    /**
     * This method extracts private key from the keystore
     *
     * @return a private key stored in the keystore {@link java.security.PrivateKey}
     */
    public PrivateKey getPrivateKey() throws KeyStoreException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException {
        return (PrivateKey) readKeystore().getKey(this.keyAlias, this.keyStorePassword.toCharArray());
    }

    /**
     * This method extracts a public key from the keystore
     *
     * @return a public key stored in the keystore {@link java.security.PublicKey}
     */
    public PublicKey getPublicKey() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        X509Certificate x509Certificate = (X509Certificate) readKeystore().getCertificate("1");
        return x509Certificate.getPublicKey();
    }
}

