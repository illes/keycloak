package org.keycloak.jose.jws;

import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.models.KeycloakSession;

public class ES512TokenSignatureProviderFactory implements TokenSignatureProviderFactory {

    public static final String ID = Algorithm.ES512.name();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public TokenSignatureProvider create(KeycloakSession session) {
        return new ESTokenSignatureProvider(session, Algorithm.ES512.name(), JavaAlgorithm.ES512);
    }

}
