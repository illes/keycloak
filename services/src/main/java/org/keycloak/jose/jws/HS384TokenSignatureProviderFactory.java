package org.keycloak.jose.jws;

import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.models.KeycloakSession;

public class HS384TokenSignatureProviderFactory implements TokenSignatureProviderFactory  {

    public static final String ID = Algorithm.RS384.name();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public TokenSignatureProvider create(KeycloakSession session) {
        return new HMACTokenSignatureProvider(session, Algorithm.RS384.name(), JavaAlgorithm.HS384);
    }

}
