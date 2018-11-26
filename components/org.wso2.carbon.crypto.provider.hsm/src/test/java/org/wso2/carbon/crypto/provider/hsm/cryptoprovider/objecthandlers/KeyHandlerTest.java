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

package org.wso2.carbon.crypto.provider.hsm.cryptoprovider.objecthandlers;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.DES2SecretKey;
import iaik.pkcs.pkcs11.objects.DES3SecretKey;
import iaik.pkcs.pkcs11.objects.DESSecretKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.SecretKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.provider.hsm.TestUtil;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.exception.HSMCryptoException;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.KeyTemplateGenerator;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.SessionHandler;

public class KeyHandlerTest {

    private SessionHandler sessionHandler;
    private Session session;
    private KeyHandler keyHandler;
    private String keyAliasNotInHSM = "notInsideHSM";

    @BeforeClass
    public void setUpClass() {

        sessionHandler = TestUtil.getSessionHandler();
    }

    @BeforeMethod
    public void setUp() {

        try {
            session = sessionHandler.initiateSession(0, null, true);
            keyHandler = new KeyHandler(session);
        } catch (CryptoException e) {
            System.out.println("Error occurred while initiating a session : " + e.getMessage());
        }
    }

    @AfterMethod
    public void tearDown() {

        try {
            sessionHandler.closeSession(session);
        } catch (CryptoException e) {
            System.out.println("Error occurred while closing the session : " + e.getMessage());
        }
    }

    @Test(dataProvider = "sampleKeyRetrievalData")
    public void testRetrieveKey(Key keyTemplate) {

        try {
            Key key = keyHandler.retrieveKey(keyTemplate);
            Assert.assertEquals(String.valueOf(key.getLabel().getCharArrayValue()),
                    String.valueOf(keyTemplate.getLabel().getCharArrayValue()));
            Assert.assertTrue(key.getObjectHandle() != -1);
        } catch (CryptoException e) {
            if (keyAliasNotInHSM.equals(String.valueOf(keyTemplate.getLabel().getCharArrayValue()))) {
                Assert.assertEquals(e.getMessage(), String.format("Requested key with key alias %s can't be " +
                        "found inside the HSM", String.valueOf(keyTemplate.getLabel().getCharArrayValue())));
            } else {
                System.out.println("Error occurred while retrieving key : " + e.getMessage());
            }
        }
    }

    @DataProvider(name = "sampleKeyRetrievalData")
    public Object[][] getSampleKeyData() {

        ;

        return new Object[][]{
                {
                        generateTemplate(new PrivateKey(), "wso2carbon")
                },
                {
                        generateTemplate(new PublicKey(), "wso2carbon")
                },
                {
                        generateTemplate(new SecretKey(), "sample")
                },
                {
                        generateTemplate(new PublicKey(), keyAliasNotInHSM)
                }
        };
    }

    @Test(dataProvider = "sampleSecretKeyGeneratorDataProvider")
    public void testGenerateSecretKey(SecretKey secretKeyTemplate, Mechanism keyGenerationMechanism) {

        try {
            SecretKey secretKey = keyHandler.generateSecretKey(secretKeyTemplate, keyGenerationMechanism);
            Assert.assertTrue(secretKey.getObjectHandle() != -1);
            Assert.assertNotNull(secretKey.getCheckValue().getByteArrayValue());
        } catch (HSMCryptoException e) {
            System.out.println("Error occurred while generating secret key : " + e.getMessage() + " : " +
                    e.getErrorCode());
        }
    }

    @DataProvider(name = "sampleSecretKeyGeneratorDataProvider")
    public Object[][] getSampleSecretKeyData() {

        AESSecretKey aesSecretKey = KeyTemplateGenerator.generateAESKeyTemplate();
        aesSecretKey.getValueLen().setLongValue(16L);

        DESSecretKey desSecretKey = KeyTemplateGenerator.generateDESKeyTemplate();

        DES2SecretKey des2SecretKey = KeyTemplateGenerator.generateDES2KeyTemplate();

        DES3SecretKey des3SecretKey = KeyTemplateGenerator.generateDES3KeyTemplate();

        AESSecretKey aesSecretKey1 = KeyTemplateGenerator.generateAESKeyTemplate();
        aesSecretKey1.getValueLen().setLongValue(16L);

        return new Object[][]{
                {
                        aesSecretKey, Mechanism.get(PKCS11Constants.CKM_AES_KEY_GEN)
                },
                {
                        desSecretKey, Mechanism.get(PKCS11Constants.CKM_DES_KEY_GEN)
                },
                {
                        des2SecretKey, Mechanism.get(PKCS11Constants.CKM_DES2_KEY_GEN)
                },
                {
                        des3SecretKey, Mechanism.get(PKCS11Constants.CKM_DES3_KEY_GEN)
                },
                {
                        aesSecretKey1, Mechanism.get(PKCS11Constants.CKM_DES2_KEY_GEN)
                }
        };
    }

    @Test(dataProvider = "sampleSecretKeyHandleDataProvider")
    public void testGetSecretKeyHandle(SecretKey secretKey) {

        try {
            SecretKey secretKeyWithHandle = (SecretKey) keyHandler.getKeyHandle(secretKey);
            Assert.assertTrue(secretKeyWithHandle.getObjectHandle() != -1);
            Assert.assertNotNull(secretKeyWithHandle.getCheckValue().getByteArrayValue());
        } catch (HSMCryptoException e) {
            System.out.println(e.getMessage());
        }
    }

    @DataProvider(name = "sampleSecretKeyHandleDataProvider")
    public Object[][] getSampleSecretKeyHandleData() {

        AESSecretKey aesSecretKey = KeyTemplateGenerator.generateAESKeyTemplate();
        aesSecretKey.getValue().setByteArrayValue(new byte[16]);

        AESSecretKey aesSecretKey2 = KeyTemplateGenerator.generateAESKeyTemplate();
        aesSecretKey2.getValue().setByteArrayValue(new byte[32]);

        DES2SecretKey des2SecretKey = KeyTemplateGenerator.generateDES2KeyTemplate();
        des2SecretKey.getValue().setByteArrayValue(new byte[16]);

        DES3SecretKey des3SecretKey = KeyTemplateGenerator.generateDES3KeyTemplate();
        des3SecretKey.getValue().setByteArrayValue(new byte[24]);

        return new Object[][]{
                {
                        aesSecretKey
                },
                {
                        aesSecretKey2
                },
                {
                        des2SecretKey
                },
                {
                        des3SecretKey
                }
        };
    }

    protected Key generateTemplate(Key keyTemplate, String keyAlias) {

        keyTemplate.getLabel().setCharArrayValue(keyAlias.toCharArray());
        return keyTemplate;
    }
}
