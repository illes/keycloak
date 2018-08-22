package org.keycloak.jose.jws;

import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;

public class TokenSignatureUtil {

    private static String DEFAULT_ALGORITHM_NAME = "RS256";

    public static String getRefreshTokenSignatureAlgorithm(RealmModel realm, ClientModel client) {
        return getTokenSignatureAlgorithm(realm, client, null);
    }

    public static String getAccessTokenSignatureAlgorithm(RealmModel realm, ClientModel client) {
        return getTokenSignatureAlgorithm(realm, client, OIDCConfigAttributes.ACCESS_TOKEN_SIGNED_RESPONSE_ALG);
    }

    public static String getIdTokenSignatureAlgorithm(RealmModel realm, ClientModel client) {
        return getTokenSignatureAlgorithm(realm, client, OIDCConfigAttributes.ID_TOKEN_SIGNED_RESPONSE_ALG);
    }

    public static String getUserinfoSignatureAlgorithm(RealmModel realm, ClientModel client) {
        return getTokenSignatureAlgorithm(realm, client, OIDCConfigAttributes.USER_INFO_RESPONSE_SIGNATURE_ALG);
    }

    private static String getTokenSignatureAlgorithm(RealmModel realm, ClientModel client, String clientAttribute) {
        String algorithm = client != null && clientAttribute != null ? client.getAttribute(clientAttribute) : null;
        if (algorithm != null && !algorithm.equals("")) {
            return algorithm;
        }

        algorithm = realm.getDefaultSignatureAlgorithm();
        if (algorithm != null && !algorithm.equals("")) {
            return algorithm;
        }

        return DEFAULT_ALGORITHM_NAME;
    }

}
