package org.keycloak.jose.jws;

import org.keycloak.common.VerificationException;

import java.security.MessageDigest;

public class SecretSignatureVerifierContext implements SignatureVerifierContext {

    private final SignatureContext signer;

    public SecretSignatureVerifierContext(SignatureContext signer) {
        this.signer = signer;
    }

    @Override
    public String getKid() {
        return signer.getKid();
    }

    @Override
    public String getAlgorithm() {
        return signer.getAlgorithm();
    }

    @Override
    public boolean verify(byte[] data, byte[] signature) throws VerificationException {
        try {
            byte[] signatureCheck = signer.sign(data);
            return MessageDigest.isEqual(signatureCheck, signature);
        } catch (Exception e) {
            throw new VerificationException("Signing failed", e);
        }
    }

}
