package org.keycloak.jose.jws;

import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;

import org.keycloak.common.util.Base64Url;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.models.KeycloakSession;

public class HMACTokenSignatureProvider implements TokenSignatureProvider {

    private String javaAlgorithm;

    public HMACTokenSignatureProvider(String javaAlgorithm) {
        this.javaAlgorithm = javaAlgorithm;
    }

    @Override
    public byte[] sign(byte[] data, Key key) {
        try {
            Mac mac = Mac.getInstance(javaAlgorithm);
            mac.init(key);
            mac.update(data);
            return mac.doFinal();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean verify(JWSInput jws, Key verifyKey) {
        try {
            byte[] signature = sign(jws.getEncodedSignatureInput().getBytes("UTF-8"), verifyKey);
            return MessageDigest.isEqual(signature, Base64Url.decode(jws.getEncodedSignature()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
