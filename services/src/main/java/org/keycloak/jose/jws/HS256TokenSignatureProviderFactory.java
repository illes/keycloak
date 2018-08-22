package org.keycloak.jose.jws;

import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.models.KeycloakSession;

public class HS256TokenSignatureProviderFactory implements TokenSignatureProviderFactory  {

    public static final String ID = Algorithm.HS256.name();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public TokenSignatureProvider create(KeycloakSession session) {
        return new HMACTokenSignatureProvider(session, Algorithm.HS256.name(), JavaAlgorithm.HS256);
    }

}
