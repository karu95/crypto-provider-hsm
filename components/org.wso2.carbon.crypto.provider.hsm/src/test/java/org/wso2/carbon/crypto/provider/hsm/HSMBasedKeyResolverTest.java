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

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.api.CertificateInfo;
import org.wso2.carbon.crypto.api.CryptoContext;
import org.wso2.carbon.crypto.api.PrivateKeyInfo;

import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_ID;

public class HSMBasedKeyResolverTest {

    private static final String PRIMARY_KEYSTORE_KEY_ALIAS_PROPERTY_PATH = "Security.KeyStore.KeyAlias";
    private static final String PRIMARY_KEYSTORE_KEY_PASSWORD_PROPERTY_PATH = "Security.KeyStore.KeyPassword";

    private HSMBasedKeyResolver hsmBasedKeyResolver;
    private ServerConfigurationService serverConfigurationService;

    @BeforeClass
    public void setUpClass() {

        serverConfigurationService = TestUtil.getServerConfigurationService();
        hsmBasedKeyResolver = new HSMBasedKeyResolver(serverConfigurationService);
    }

    @Test(dataProvider = "sampleKeyResolverDataProvider")
    public void testIsApplicable(CryptoContext cryptoContext) {

        Assert.assertTrue(hsmBasedKeyResolver.isApplicable(cryptoContext));
    }

    @Test(dataProvider = "sampleKeyResolverDataProvider")
    public void testGetPrivateKeyInfo(CryptoContext cryptoContext) {

        PrivateKeyInfo privateKeyInfo = hsmBasedKeyResolver.getPrivateKeyInfo(cryptoContext);

        if (SUPER_TENANT_ID == cryptoContext.getTenantId()) {
            Assert.assertEquals(privateKeyInfo.getKeyAlias(),
                    serverConfigurationService.getFirstProperty(PRIMARY_KEYSTORE_KEY_ALIAS_PROPERTY_PATH));
            Assert.assertEquals(privateKeyInfo.getKeyPassword(),
                    serverConfigurationService.getFirstProperty(PRIMARY_KEYSTORE_KEY_PASSWORD_PROPERTY_PATH));
        } else {
            Assert.assertEquals(privateKeyInfo.getKeyAlias(), cryptoContext.getTenantDomain());
            Assert.assertNull(privateKeyInfo.getKeyPassword());
        }
    }

    @Test(dataProvider = "sampleKeyResolverDataProvider")
    public void testGetCertificateInfo(CryptoContext cryptoContext) {

        CertificateInfo certificateInfo = hsmBasedKeyResolver.getCertificateInfo(cryptoContext);
        if (SUPER_TENANT_ID == cryptoContext.getTenantId()) {
            Assert.assertEquals(certificateInfo.getCertificateAlias(),
                    serverConfigurationService.getFirstProperty(PRIMARY_KEYSTORE_KEY_ALIAS_PROPERTY_PATH));
            ;
        } else {
            Assert.assertEquals(certificateInfo.getCertificateAlias(), cryptoContext.getTenantDomain());
        }
    }

    @DataProvider(name = "sampleKeyResolverDataProvider")
    public Object[][] getSampleCryptoContexts() {

        return new Object[][]{
                {
                        CryptoContext.buildEmptyContext(-1234, "carbon.super")
                },
                {
                        CryptoContext.buildEmptyContext(12, "abc.com")
                },
                {
                        CryptoContext.buildEmptyContext(1231, "def.com")
                }
        };
    }
}