package org.keycloak.jose.jws;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderFactory;

// KEYCLOAK-7560 Refactoring Token Signing and Verifying by Token Signature SPI

public interface TokenSignatureProviderFactory<T extends TokenSignatureProvider> extends ProviderFactory<TokenSignatureProvider> {

    @Override
    default void init(Config.Scope config) {
    }

    @Override
    default void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    default void close() {
    }

}
