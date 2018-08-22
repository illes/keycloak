package org.keycloak.jose.jws;

import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.models.KeycloakSession;

public class RS256TokenSignatureProviderFactory implements TokenSignatureProviderFactory {

    public static final String ID = Algorithm.RS256.name();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public TokenSignatureProvider create(KeycloakSession session) {
        return new RSTokenSignatureProvider(session, Algorithm.RS256.name(), JavaAlgorithm.RS256);
    }

}
