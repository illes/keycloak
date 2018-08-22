package org.keycloak.jose.jws;

import org.keycloak.provider.Provider;

public interface TokenSignatureProvider extends Provider {

    SignatureContext signer() throws SignatureException;

    SignatureVerifierContext verifier(String kid) throws SignatureException;

    @Override
    default void close() {
    }

}
