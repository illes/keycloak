package org.keycloak.jose.jws;

import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;

import javax.crypto.Mac;

public class SecretSignatureContext implements SignatureContext {

    private final String algorithm;
    private final String javaAlgorithm;
    private final KeyWrapper key;

    public SecretSignatureContext(KeycloakSession session, String algorithm, String javaAlgorithm) throws SignatureException {
        this.algorithm = algorithm;
        this.javaAlgorithm = javaAlgorithm;
        this.key = session.keys().getActiveKey(session.getContext().getRealm(), KeyUse.SIG, algorithm);
        if (key == null) {
            throw new SignatureException("Active key for " + algorithm + " not found");
        }
    }

    @Override
    public String getKid() {
        return key.getKid();
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public byte[] sign(byte[] data) throws SignatureException {
        try {
            Mac mac = Mac.getInstance(javaAlgorithm);
            mac.init(key.getSecretKey());
            mac.update(data);
            return mac.doFinal();
        } catch (Exception e) {
            throw new SignatureException("Signing failed", e);
        }
    }

}
