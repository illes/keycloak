package org.keycloak.jose.jws;

import org.jboss.logging.Logger;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.util.TokenUtil;

import java.security.Key;

public class TokenSignature {

    private static final Logger logger = Logger.getLogger(TokenSignature.class);

    KeycloakSession session;
    RealmModel realm;
    String sigAlgName;

    public static TokenSignature getInstance(KeycloakSession session, RealmModel realm, String sigAlgName) {
        return new TokenSignature(session, realm, sigAlgName);
    }

    public TokenSignature(KeycloakSession session, RealmModel realm, String sigAlgName) {
        this.session = session;
        this.realm = realm;
        this.sigAlgName = sigAlgName;
    }

    public String sign(JsonWebToken jwt) {
        TokenSignatureProvider tokenSignatureProvider = session.getProvider(TokenSignatureProvider.class, sigAlgName);
        if (tokenSignatureProvider == null) return null;

        KeyWrapper keyWrapper = session.keys().getActiveKey(realm, KeyUse.SIG, sigAlgName);
        if (keyWrapper == null) return null;

        String keyId = keyWrapper.getKid();
        Key signKey = keyWrapper.getSignKey();
        String encodedToken = new JWSBuilder().type("JWT").kid(keyId).jsonContent(jwt).sign((JWSSignatureProvider)tokenSignatureProvider, sigAlgName, signKey);
        return encodedToken;
    }

    public boolean verify(JWSInput jws) throws JWSInputException {
        TokenSignatureProvider tokenSignatureProvider = session.getProvider(TokenSignatureProvider.class, sigAlgName);
        if (tokenSignatureProvider == null) return false;

        KeyWrapper keyWrapper = null;
        // Backwards compatibility. Old offline tokens didn't have KID in the header
        if (jws.getHeader().getKeyId() == null && isOfflineToken(jws)) {
            logger.debugf("KID is null in offline token. Using the realm active key to verify token signature.");
            keyWrapper = session.keys().getActiveKey(realm, KeyUse.SIG, sigAlgName);
        } else {
            keyWrapper = session.keys().getKey(realm, jws.getHeader().getKeyId(), KeyUse.SIG, sigAlgName);
        }
        if (keyWrapper == null) return false;

        return tokenSignatureProvider.verify(jws, keyWrapper.getVerifyKey());
    }

    private boolean isOfflineToken(JWSInput jws) throws JWSInputException {
        RefreshToken token = TokenUtil.getRefreshToken(jws.getContent());
        return token.getType().equals(TokenUtil.TOKEN_TYPE_OFFLINE);
    }

}
