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

package org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util;

import iaik.pkcs.pkcs11.Mechanism;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.crypto.api.CryptoException;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class MechanismResolverTest {

    private MechanismResolver mechanismResolver;

    @BeforeClass
    public void setUpClass() {

        this.mechanismResolver = MechanismResolver.getInstance();
    }

    @Test
    public void testGetSupportedMechanisms() {

        Assert.assertNotNull(MechanismResolver.getSupportedMechanisms());
    }

    @Test(dataProvider = "mechanismDataProvider")
    public void testResolveMechanism(MechanismDataHolder mechanismDataHolder) {

        try {
            Mechanism mechanism = mechanismResolver.resolveMechanism(mechanismDataHolder);
            Assert.assertEquals(mechanism.getMechanismCode(), (long) MechanismResolver.getSupportedMechanisms()
                    .get(mechanismDataHolder.getJceMechanismSpecification()));
        } catch (CryptoException e) {
            if (!MechanismResolver.getSupportedMechanisms().containsKey(mechanismDataHolder.getJceMechanismSpecification())) {
                Assert.assertEquals(e.getMessage(), String.format("Requested %s algorithm is not supported by " +
                        "HSM based crypto provider.", mechanismDataHolder.getJceMechanismSpecification()));
            }
        }
    }

    @DataProvider(name = "mechanismDataProvider")
    public Object[][] getMechanismData() {

        MechanismDataHolder mechanismDataHolder1 = new MechanismDataHolder(CryptoConstants.VERIFY_MODE,
                "SHA256withRSAandMGF1");
        MechanismDataHolder mechanismDataHolder2 = new MechanismDataHolder(CryptoConstants.SIGN_MODE,
                "SHA256withRSAandMGF1");

        MechanismDataHolder mechanismDataHolder3 = new MechanismDataHolder(CryptoConstants.ENCRYPT_MODE,
                "DES/CBC/PKCS5Padding");
        MechanismDataHolder mechanismDataHolder4 = new MechanismDataHolder(CryptoConstants.DECRYPT_MODE,
                "DES/CBC/PKCS5Padding", new IvParameterSpec(new byte[8]));

        MechanismDataHolder mechanismDataHolder5 = new MechanismDataHolder(CryptoConstants.ENCRYPT_MODE,
                "AES/CBC/PKCS5Padding");
        MechanismDataHolder mechanismDataHolder6 = new MechanismDataHolder(CryptoConstants.DECRYPT_MODE,
                "AES/CBC/PKCS5Padding", new IvParameterSpec(new byte[16]));

        MechanismDataHolder mechanismDataHolder7 = new MechanismDataHolder(CryptoConstants.ENCRYPT_MODE,
                "AES/GCM/NoPadding", new byte[16]);
        MechanismDataHolder mechanismDataHolder8 = new MechanismDataHolder(CryptoConstants.DECRYPT_MODE,
                "AES/GCM/NoPadding", new GCMParameterSpec(128, new byte[12]), new byte[16]);

        MechanismDataHolder mechanismDataHolder9 = new MechanismDataHolder(CryptoConstants.ENCRYPT_MODE,
                "RSA/ECB/OAEPwithSHA224andMGF1Padding");
        MechanismDataHolder mechanismDataHolder10 = new MechanismDataHolder(CryptoConstants.DECRYPT_MODE,
                "RSA/ECB/OAEPwithSHA224andMGF1Padding");

        MechanismDataHolder mechanismDataHolder11 = new MechanismDataHolder(CryptoConstants.ENCRYPT_MODE, "asdsadsa");

        return new Object[][]{
                {
                        mechanismDataHolder1
                },
                {
                        mechanismDataHolder2
                },
                {
                        mechanismDataHolder3
                },
                {
                        mechanismDataHolder4
                },
                {
                        mechanismDataHolder5
                },
                {
                        mechanismDataHolder6
                },
                {
                        mechanismDataHolder7
                },
                {
                        mechanismDataHolder8
                },
                {
                        mechanismDataHolder9
                },
                {
                        mechanismDataHolder10
                },
                {
                        mechanismDataHolder11
                }
        };
    }

}