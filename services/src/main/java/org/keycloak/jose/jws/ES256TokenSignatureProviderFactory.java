package org.keycloak.jose.jws;

import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.models.KeycloakSession;

public class ES256TokenSignatureProviderFactory implements TokenSignatureProviderFactory {

    public static final String ID = Algorithm.ES256.name();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public TokenSignatureProvider create(KeycloakSession session) {
        return new ECDSATokenSignatureProvider(JavaAlgorithm.ES256);
    }

}
