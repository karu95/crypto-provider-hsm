/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

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

    /**
     * Constructor of HSM based key resolver.
     *
     * @param serverConfigurationService : carbon.xml configuration is provided using this service.
     */
    public HSMBasedKeyResolver(ServerConfigurationService serverConfigurationService) {

        this.serverConfigurationService = serverConfigurationService;
    }

    /**
     * Checks if the given context can be resolved by this Key Resolver.
     *
     * @param cryptoContext Context information related to the cryptographic operation.
     * @return
     */
    @Override
    public boolean isApplicable(CryptoContext cryptoContext) {

        return true;
    }

    /**
     * Returns private key information related to given {@link CryptoContext}.
     *
     * @param cryptoContext Context information related to the cryptographic operation.
     * @return
     */
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

    /**
     * Returns certificate information related to given {@link CryptoContext}.
     *
     * @param cryptoContext Context information related to the cryptographic operation.
     * @return {@link CertificateInfo} instance.
     */
    @Override
    public CertificateInfo getCertificateInfo(CryptoContext cryptoContext) {

        String certificateAlias;
        if (SUPER_TENANT_ID == cryptoContext.getTenantId()) {
            certificateAlias = serverConfigurationService.getFirstProperty(PRIMARY_KEYSTORE_KEY_ALIAS_PROPERTY_PATH);
        } else {
            certificateAlias = cryptoContext.getTenantDomain();
        }

        return new CertificateInfo(certificateAlias, null);
    }
}
