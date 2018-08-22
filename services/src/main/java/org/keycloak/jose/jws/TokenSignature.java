package org.keycloak.jose.jws;

import org.jboss.logging.Logger;
import org.keycloak.crypto.KeyUse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.util.TokenUtil;

public class TokenSignature {

    private static final Logger logger = Logger.getLogger(TokenSignature.class);

    private TokenSignature() {
    }

    public static String sign(KeycloakSession session, String sigAlgName, JsonWebToken jwt) {
        SignatureContext signer;
        try {
            TokenSignatureProvider tokenSignatureProvider = session.getProvider(TokenSignatureProvider.class, sigAlgName);
            if (tokenSignatureProvider == null) {
                return null;
            }
            signer = tokenSignatureProvider.signer();
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }

        String encodedToken = new JWSBuilder().type("JWT").jsonContent(jwt).sign(signer);
        return encodedToken;
    }

    public static boolean verify(KeycloakSession session, JWSInput jws) throws JWSInputException {
        String sigAlgName = jws.getHeader().getAlgorithm().name();

        TokenSignatureProvider tokenSignatureProvider = session.getProvider(TokenSignatureProvider.class, sigAlgName);
        if (tokenSignatureProvider == null) return false;

        String kid = jws.getHeader().getKeyId();
        // Backwards compatibility. Old offline tokens didn't have KID in the header
        if (kid == null && isOfflineToken(jws)) {
            logger.debugf("KID is null in offline token. Using the realm active key to verify token signature.");
            kid = session.keys().getActiveKey(session.getContext().getRealm(), KeyUse.SIG, sigAlgName).getKid();
        }

        try {
            return tokenSignatureProvider.verifier(kid).verify(jws.getEncodedSignatureInput().getBytes("UTF-8"), jws.getSignature());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean isOfflineToken(JWSInput jws) throws JWSInputException {
        RefreshToken token = TokenUtil.getRefreshToken(jws.getContent());
        return token.getType().equals(TokenUtil.TOKEN_TYPE_OFFLINE);
    }

}
