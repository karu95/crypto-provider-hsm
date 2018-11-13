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
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.MechanismResolver;

import java.util.ArrayList;

public class HSMBasedInternalCryptoProviderTest {

    private HSMBasedInternalCryptoProvider hsmBasedInternalCryptoProvider;
    private ArrayList<byte[]> samplePlainData = new ArrayList<>();
    private ArrayList<byte[]> sampleEncryptedData = new ArrayList<>();

    @BeforeClass
    public void setUpClass() {

        try {
            hsmBasedInternalCryptoProvider = new HSMBasedInternalCryptoProvider(TestUtil.getServerConfigurationService());
        } catch (CryptoException e) {
            System.out.println("Error occurred during instantiating HSMBasedInternalCryptoProvider : " + e.getMessage());
        }
    }

    @Test(dataProvider = "sampleEncryptionDataProvider")
    public void testEncrypt(byte[] cleartext, String algorithm, String javaSecurityAPIProvider) {

        try {
            byte[] encryptedData = hsmBasedInternalCryptoProvider.encrypt(cleartext, algorithm, javaSecurityAPIProvider);
            sampleEncryptedData.add(encryptedData);
        } catch (CryptoException e) {
            if (!(algorithm != null && MechanismResolver.getSupportedMechanisms().containsKey(algorithm))) {
                Assert.assertEquals(e.getMessage(), String.format("Requested algorithm '%s' is not valid/supported by the " +
                        "HSM based Crypto Provider.", algorithm));
                sampleEncryptedData.add(cleartext);
            } else if (cleartext == null || cleartext.length == 0) {
                Assert.assertEquals(e.getMessage(), "Data sent for cryptographic operation is null/empty.");
                sampleEncryptedData.add(cleartext);
            } else {
                System.out.println("Error occurred while encrypting sample data : " + e.getMessage());
            }
        }
    }

    @DataProvider(name = "sampleEncryptionDataProvider")
    public Object[][] getSampleEncryptionData() {

        samplePlainData.add("Sample data to be encrypted using RSA OAEP MD5".getBytes());
        samplePlainData.add("Sample data to be encrypted using RSA OAEP SHA512".getBytes());
        samplePlainData.add("".getBytes());
        samplePlainData.add(null);
        samplePlainData.add("Invalid algorithm".getBytes());

        return new Object[][]{
                {
                        samplePlainData.get(0), "RSA/ECB/OAEPwithMD5andMGF1Padding", null
                },
                {
                        samplePlainData.get(1), "RSA/ECB/OAEPwithSHA512andMGF1Padding", null
                },
                {
                        samplePlainData.get(2), "RSA/ECB/OAEPwithSHA256andMGF1Padding", null
                },
                {
                        samplePlainData.get(3), "RSA/ECB/PKCS1Padding", null
                },
                {
                        samplePlainData.get(4), "InvalidAlgorithm", null
                }
        };
    }

    @Test(dataProvider = "sampleDecryptionDataProvider", priority = 1)
    public void testDecrypt(byte[] ciphertext, String algorithm, String javaSecurityAPIProvider,
                            byte[] testedSampleData) {

        try {
            byte[] decryptedData = hsmBasedInternalCryptoProvider.decrypt(ciphertext, algorithm, javaSecurityAPIProvider);
            Assert.assertEquals(decryptedData, testedSampleData);
        } catch (CryptoException e) {
            if (!(algorithm != null && MechanismResolver.getSupportedMechanisms().containsKey(algorithm))) {
                Assert.assertEquals(e.getMessage(), String.format("Requested algorithm '%s' is not valid/supported by the " +
                        "HSM based Crypto Provider.", algorithm));
            } else if (ciphertext == null || ciphertext.length == 0) {
                Assert.assertEquals(e.getMessage(), "Data sent for cryptographic operation is null/empty.");
            } else {
                System.out.println("Error occurred while decrypting test data : " + e.getMessage());
            }
        }
    }

    @DataProvider(name = "sampleDecryptionDataProvider")
    public Object[][] getSampleDecryptionData() {

        return new Object[][]{
                {
                        sampleEncryptedData.get(0), "RSA/ECB/OAEPwithMD5andMGF1Padding", null,
                        samplePlainData.get(0)
                },
                {
                        sampleEncryptedData.get(1), "RSA/ECB/OAEPwithSHA512andMGF1Padding", null,
                        samplePlainData.get(1)
                },
                {
                        sampleEncryptedData.get(2), "RSA/ECB/OAEPwithSHA256andMGF1Padding", null,
                        samplePlainData.get(2)
                },
                {
                        sampleEncryptedData.get(3), "RSA/ECB/PKCS1Padding", null, samplePlainData.get(3)
                },
                {
                        sampleEncryptedData.get(4), "InvalidAlgorithm", null, samplePlainData.get(4)
                }
        };
    }
}