package org.keycloak.jose.jws;

import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.models.KeycloakSession;

public class RS512TokenSignatureProviderFactory implements TokenSignatureProviderFactory {

    public static final String ID = Algorithm.RS512.name();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public TokenSignatureProvider create(KeycloakSession session) {
        return new RSTokenSignatureProvider(session, Algorithm.RS512.name(), JavaAlgorithm.RS512);
    }

}
