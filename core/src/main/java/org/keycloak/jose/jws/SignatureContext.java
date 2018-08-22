package org.keycloak.jose.jws;

public interface SignatureContext {

    String getKid();

    String getAlgorithm();

    byte[] sign(byte[] data) throws SignatureException;

}
