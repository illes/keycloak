package org.keycloak.jose.jws;

import org.keycloak.provider.Provider;

import java.security.Key;

public interface TokenSignatureProvider extends Provider, JWSSignatureProvider {

    byte[] sign(byte[] data, Key key);

    boolean verify(JWSInput input, Key key);

    @Override
    default void close() {
    }

}
