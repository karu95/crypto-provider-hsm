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

package org.wso2.carbon.crypto.provider.hsm.cryptoprovider.operators;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.SecretKey;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.provider.hsm.TestUtil;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.objecthandlers.KeyHandler;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.MechanismDataHolder;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.MechanismResolver;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.SessionHandler;

import java.util.ArrayList;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import static org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.CryptoConstants.DECRYPT_MODE;
import static org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.CryptoConstants.ENCRYPT_MODE;

public class CipherTest {

    private Cipher cipher;
    private SessionHandler sessionHandler;
    private Session session;
    private MechanismResolver mechanismResolver;
    private KeyHandler keyHandler;
    private ArrayList<byte[]> sampleEncryptedData = new ArrayList<>();
    private ArrayList<byte[]> sampleDataToBeEncrypted = new ArrayList<>();
    private ArrayList<byte[]> ivs = new ArrayList<>();

    @BeforeClass
    public void setUpClass() {

        sessionHandler = TestUtil.getSessionHandler();
        mechanismResolver = MechanismResolver.getInstance();
    }

    @BeforeMethod
    public void setUp() {

        try {
            session = sessionHandler.initiateSession(0, false);
            keyHandler = new KeyHandler(session);
            cipher = new Cipher(session);
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

    @Test(dataProvider = "sampleEncryptionDataProvider")
    public void testEncrypt(byte[] dataToBeEncrypted, Key encryptionKeyTemplate, Mechanism encryptionMechanism) {

        try {
            Key encryptionKey = keyHandler.retrieveKey(encryptionKeyTemplate);
            byte[] encryptedData = cipher.encrypt(dataToBeEncrypted, encryptionKey, encryptionMechanism);
            sampleEncryptedData.add(encryptedData);
            if (encryptionMechanism.getParameters() instanceof InitializationVectorParameters) {
                ivs.add(((InitializationVectorParameters) encryptionMechanism.getParameters()).getInitializationVector());
            }
        } catch (CryptoException e) {
            sampleEncryptedData.add(dataToBeEncrypted);
            System.out.println("Error occurred while encrypting data : " + e.getMessage());
        }
    }

    @DataProvider(name = "sampleEncryptionDataProvider")
    public Object[][] getSampleEncryptionData() {

        try {
            sampleDataToBeEncrypted.add("sample data for RSA OAEP".getBytes());
            sampleDataToBeEncrypted.add("sample encryption for RSA".getBytes());
            sampleDataToBeEncrypted.add("sample data set AES".getBytes());
            sampleDataToBeEncrypted.add("sample encryption for DES".getBytes());

            return new Object[][]{
                    {
                            sampleDataToBeEncrypted.get(0), getKey(new PublicKey(), "wso2carbon"), mechanismResolver
                            .resolveMechanism(new MechanismDataHolder(ENCRYPT_MODE, "RSA/ECB/OAEPwithMD5andMGF1Padding"))
                    },
                    {
                            sampleDataToBeEncrypted.get(1), getKey(new PublicKey(), "wso2carbon"), mechanismResolver
                            .resolveMechanism(new MechanismDataHolder(ENCRYPT_MODE, "RSA/ECB/PKCS1Padding"))
                    },
                    {
                            sampleDataToBeEncrypted.get(2), getKey(new SecretKey(), "sample"), mechanismResolver
                            .resolveMechanism(new MechanismDataHolder(ENCRYPT_MODE, "AES/CBC/PKCS5Padding"))
                    },
                    {
                            sampleDataToBeEncrypted.get(3), getKey(new SecretKey(), "DES3 Secret Key"), mechanismResolver
                            .resolveMechanism(new MechanismDataHolder(ENCRYPT_MODE, "3DES/CBC/PKCS5Padding"))
                    },
                    {
                            sampleDataToBeEncrypted.get(0), new PrivateKey(), mechanismResolver.resolveMechanism(new
                            MechanismDataHolder(ENCRYPT_MODE, "AES/GCM/NoPadding", new byte[30]))
                    },
                    {
                            sampleDataToBeEncrypted.get(0), new PrivateKey(), mechanismResolver.resolveMechanism(new
                            MechanismDataHolder(ENCRYPT_MODE, "SHA256withRSA", new byte[30]))
                    }
            };
        } catch (CryptoException e) {
            System.out.println("Error occurred during resolving mechanism : " + e.getMessage());
            return null;
        }
    }

    @Test(dataProvider = "sampleDecryptionDataProvider", priority = 1)
    public void testDecrypt(byte[] dataToBeDecrypted, Key decryptionKeyTemplate, Mechanism decryptionMechanism,
                            byte[] expectedDecryptedData) {

        try {
            Key decryptionKey = keyHandler.retrieveKey(decryptionKeyTemplate);
            byte[] decryptedData = cipher.decrypt(dataToBeDecrypted, decryptionKey, decryptionMechanism);
            Assert.assertEquals(decryptedData, expectedDecryptedData);
        } catch (CryptoException e) {
            System.out.println("Error occurred while decrypting data : " + e.getMessage());
        }
    }

    @DataProvider(name = "sampleDecryptionDataProvider")
    public Object[][] getSampleDecryptionData() {

        try {
            return new Object[][]{
                    {
                            sampleEncryptedData.get(0), getKey(new PrivateKey(), "wso2carbon"),
                            mechanismResolver.resolveMechanism(new MechanismDataHolder(DECRYPT_MODE,
                                    "RSA/ECB/OAEPwithMD5andMGF1Padding")), sampleDataToBeEncrypted.get(0)
                    },
                    {
                            sampleEncryptedData.get(1), getKey(new PrivateKey(), "wso2carbon"), mechanismResolver
                            .resolveMechanism(new MechanismDataHolder(DECRYPT_MODE,
                            "RSA/ECB/PKCS1Padding")), sampleDataToBeEncrypted.get(1)
                    },
                    {
                            sampleEncryptedData.get(2), getKey(new SecretKey(), "sample"), mechanismResolver
                            .resolveMechanism(new MechanismDataHolder(DECRYPT_MODE, "AES/CBC/PKCS5Padding",
                            new IvParameterSpec(ivs.get(0)))), sampleDataToBeEncrypted.get(2)
                    },
                    {
                            sampleEncryptedData.get(3), getKey(new SecretKey(), "DES3 Secret Key"), mechanismResolver
                            .resolveMechanism(new MechanismDataHolder(DECRYPT_MODE,
                            "3DES/CBC/PKCS5Padding", new IvParameterSpec(ivs.get(1)))), sampleDataToBeEncrypted.get(3)
                    },
                    {
                            sampleEncryptedData.get(4), new AESSecretKey(), mechanismResolver.resolveMechanism(new
                            MechanismDataHolder(DECRYPT_MODE, "AES/GCM/NoPadding",
                            new GCMParameterSpec(96, new byte[16]), new byte[30])), sampleDataToBeEncrypted.get(0)
                    },
                    {
                            sampleEncryptedData.get(4), new AESSecretKey(), mechanismResolver.resolveMechanism(new
                            MechanismDataHolder(DECRYPT_MODE, "SHA256withRSA",
                            new GCMParameterSpec(96, new byte[16]), new byte[30])), sampleDataToBeEncrypted.get(0)
                    }
            };
        } catch (CryptoException e) {
            System.out.println("Error occurred during resolving mechanism : " + e.getMessage());
            return null;
        }
    }

    protected Key getKey(Key keyTemplate, String keyAlias) {

        keyTemplate.getLabel().setCharArrayValue(keyAlias.toCharArray());
        return keyTemplate;
    }
}
