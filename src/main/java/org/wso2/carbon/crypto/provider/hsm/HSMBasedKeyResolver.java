package org.wso2.carbon.crypto.provider.hsm;

import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.api.CertificateInfo;
import org.wso2.carbon.crypto.api.CryptoContext;
import org.wso2.carbon.crypto.api.KeyResolver;
import org.wso2.carbon.crypto.api.PrivateKeyInfo;

import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_ID;

/**
 * Implementation of {@link KeyResolver} to resolve keys and certificates from the HSM.
 */
public class HSMBasedKeyResolver extends KeyResolver {

    private static final String PRIMARY_KEYSTORE_KEY_ALIAS_PROPERTY_PATH = "Security.KeyStore.KeyAlias";
    private static final String PRIMARY_KEYSTORE_KEY_PASSWORD_PROPERTY_PATH = "Security.KeyStore.KeyPassword";

    private ServerConfigurationService serverConfigurationService;

    public HSMBasedKeyResolver(ServerConfigurationService serverConfigurationService) {
        this.serverConfigurationService = serverConfigurationService;
    }

    @Override
    public boolean isApplicable(CryptoContext cryptoContext) {
        return true;
    }

    @Override
    public PrivateKeyInfo getPrivateKeyInfo(CryptoContext cryptoContext) {

        String keyAlias;
        String keyPassword;
        if (SUPER_TENANT_ID == cryptoContext.getTenantId()) {
            keyAlias = serverConfigurationService.getFirstProperty(PRIMARY_KEYSTORE_KEY_ALIAS_PROPERTY_PATH);
            keyPassword = serverConfigurationService.getFirstProperty(PRIMARY_KEYSTORE_KEY_PASSWORD_PROPERTY_PATH);
        } else {
            keyAlias = cryptoContext.getTenantDomain();
            keyPassword = null; // Key password will be internally handled by the KeyStoreManager
        }

        return new PrivateKeyInfo(keyAlias, keyPassword);
    }

    @Override
    public CertificateInfo getCertificateInfo(CryptoContext cryptoContext) {

        return new CertificateInfo(cryptoContext.getTenantDomain(), null);
    }
}
