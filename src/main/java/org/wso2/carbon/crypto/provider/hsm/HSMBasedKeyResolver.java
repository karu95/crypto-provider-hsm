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
        if ((cryptoContext.getIdentifier() == null) && (SUPER_TENANT_ID == cryptoContext.getTenantId())) {
            keyAlias = serverConfigurationService.getFirstProperty(PRIMARY_KEYSTORE_KEY_ALIAS_PROPERTY_PATH);
            keyPassword = serverConfigurationService.getFirstProperty(PRIMARY_KEYSTORE_KEY_PASSWORD_PROPERTY_PATH);
        } else {
            if (cryptoContext.getIdentifier() != null) {
                keyAlias = cryptoContext.getTenantDomain() + "_" + cryptoContext.getIdentifier();
            } else {
                keyAlias = cryptoContext.getTenantDomain();
            }
            keyPassword = null; // Key password will be internally handled by the KeyStoreManager
        }

        return new PrivateKeyInfo(keyAlias, keyPassword);
    }

    @Override
    public CertificateInfo getCertificateInfo(CryptoContext cryptoContext) {

        if (cryptoContext.getIdentifier() == null) {
            return new CertificateInfo(cryptoContext.getTenantDomain(), null);
        } else {
            return new CertificateInfo(cryptoContext.getTenantDomain() + "_" + cryptoContext.getIdentifier(),
                    null);
        }
    }
}
