package org.keycloak.jose.jws;

import java.security.Key;

public interface JWSSignatureProvider {

    byte[] sign(byte[] data, Key key);

    boolean verify(JWSInput input, Key key);

}
