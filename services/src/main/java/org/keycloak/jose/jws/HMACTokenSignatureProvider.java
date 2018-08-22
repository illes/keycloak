package org.keycloak.jose.jws;

import org.keycloak.models.KeycloakSession;

public class HMACTokenSignatureProvider implements TokenSignatureProvider {

    private final KeycloakSession session;
    private final String algorithm;
    private final String javaAlgorithm;

    public HMACTokenSignatureProvider(KeycloakSession session, String algorithm, String javaAlgorithm) {
        this.session = session;
        this.algorithm = algorithm;
        this.javaAlgorithm = javaAlgorithm;
    }

    @Override
    public SignatureContext signer() throws SignatureException {
        return new SecretSignatureContext(session, algorithm, javaAlgorithm);
    }

    @Override
    public SignatureVerifierContext verifier(String kid) throws SignatureException {
        return new SecretSignatureVerifierContext(session, kid, algorithm, javaAlgorithm);
    }

}
