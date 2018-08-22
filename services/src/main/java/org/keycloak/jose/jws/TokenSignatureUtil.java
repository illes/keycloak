package org.keycloak.jose.jws;

import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;

public class TokenSignatureUtil {
    private static String DEFAULT_ALGORITHM_NAME = "RS256";

    public static String getTokenSignatureAlgorithm(RealmModel realm, ClientModel client) {
        String realmSigAlgName = realm.getDefaultSignatureAlgorithm();
        String clientSigAlgname = null;
        if (client != null) clientSigAlgname = OIDCAdvancedConfigWrapper.fromClientModel(client).getIdTokenSignedResponseAlg();
        String sigAlgName = clientSigAlgname;
        if (sigAlgName == null) sigAlgName = (realmSigAlgName == null ? DEFAULT_ALGORITHM_NAME : realmSigAlgName);
        return sigAlgName;
    }
}
