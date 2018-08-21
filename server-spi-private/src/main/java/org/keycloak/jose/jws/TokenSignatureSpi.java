package org.keycloak.jose.jws;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

public class TokenSignatureSpi implements Spi {
    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return "tokenSignature";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return TokenSignatureProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return TokenSignatureProviderFactory.class;
    }
}
