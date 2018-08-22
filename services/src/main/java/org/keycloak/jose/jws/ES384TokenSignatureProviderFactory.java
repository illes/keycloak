package org.keycloak.jose.jws;

import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.models.KeycloakSession;

public class ES384TokenSignatureProviderFactory implements TokenSignatureProviderFactory {

    public static final String ID = Algorithm.ES384.name();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public TokenSignatureProvider create(KeycloakSession session) {
        return new ESTokenSignatureProvider(session, Algorithm.ES384.name(), JavaAlgorithm.ES384);
    }

}
