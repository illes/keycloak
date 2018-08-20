package org.keycloak.jose.jws;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class ECDSATokenSignatureProvider implements TokenSignatureProvider {

    private String javaAlgorithm;

    public ECDSATokenSignatureProvider(String javaAlgorithm) {
        this.javaAlgorithm = javaAlgorithm;
    }

    @Override
    public byte[] sign(byte[] data, Key key) {
        try {
            PrivateKey privateKey = (PrivateKey)key;
            Signature signature = Signature.getInstance(javaAlgorithm);
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean verify(JWSInput jws, Key verifyKey) {
        try {
            PublicKey publicKey = (PublicKey)verifyKey;
            Signature verifier = Signature.getInstance(javaAlgorithm);
            verifier.initVerify(publicKey);
            verifier.update(jws.getEncodedSignatureInput().getBytes("UTF-8"));
            return verifier.verify(jws.getSignature());
        } catch (Exception e) {
            return false;
        }
    }

}
