package org.keycloak.jose.jws;

import org.keycloak.provider.Provider;

public interface TokenSignatureProvider extends Provider, JWSSignatureProvider {

    @Override
    default void close() {
    }

}
