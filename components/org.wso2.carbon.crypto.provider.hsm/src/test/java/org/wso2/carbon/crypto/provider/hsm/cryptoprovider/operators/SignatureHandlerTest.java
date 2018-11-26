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
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
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

import static org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.CryptoConstants.SIGN_MODE;

public class SignatureHandlerTest {

    private SessionHandler sessionHandler;
    private SignatureHandler signatureHandler;
    private Session session;
    private MechanismResolver mechanismResolver;
    private KeyHandler keyHandler;
    private ArrayList<byte[]> signatures = new ArrayList<>();

    @BeforeClass
    public void setUpClass() {

        sessionHandler = TestUtil.getSessionHandler();
        mechanismResolver = MechanismResolver.getInstance();
    }

    @BeforeMethod
    public void setUp() {

        try {
            session = sessionHandler.initiateSession(0, null, false);
            signatureHandler = new SignatureHandler(session);
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

    @Test(dataProvider = "sampleSignDataProvider")
    public void testSign(byte[] dataToSign,
                         String signKeyAlias, Mechanism signMechanism) {

        try {
            PrivateKey signKey = getPrivateKey(signKeyAlias);
            byte[] signature = signatureHandler.sign(dataToSign, signKey, signMechanism);
            signatures.add(signature);
        } catch (CryptoException e) {
            if (!(signMechanism.isFullSignVerifyMechanism() || signMechanism.isSingleOperationSignVerifyMechanism())) {
                Assert.assertEquals(e.getMessage(), String.format("Requested '%s' algorithm for data signing is not a valid " +
                        "signing mechanism.", signMechanism.getName()));
            }
            System.out.println("Error occurred while signing data : " + e.getMessage());
        }
    }

    @Test(dataProvider = "sampleVerifyDataProvider", priority = 1)
    public void testVerify(byte[] dataToVerify, String keyAlias,
                           Mechanism verifyMechanism, byte[] signature, boolean expectedResult) {

        try {
            Assert.assertEquals(signatureHandler.verify(dataToVerify, signature, getPublicKey(keyAlias),
                    verifyMechanism), expectedResult);
        } catch (CryptoException e) {
            if (!(verifyMechanism.isFullSignVerifyMechanism())) {
                Assert.assertEquals(e.getMessage(), String.format("Requested '%s' algorithm for signature verification is not a " +
                        "valid sign verification mechanism.", verifyMechanism.getName()));
            }
            System.out.println("Error occurred while signing data : " + e.getMessage());
        }
    }

    @DataProvider(name = "sampleSignDataProvider")
    public Object[][] getSampleSignData() {

        try {
            return new Object[][]{
                    {
                            "Sample Data to be signed".getBytes(), "wso2carbon",
                            mechanismResolver.resolveMechanism(new MechanismDataHolder(SIGN_MODE, "SHA512withRSAandMGF1"))
                    },
                    {
                            "".getBytes(), "wso2carbon", mechanismResolver
                            .resolveMechanism(new MechanismDataHolder(SIGN_MODE, "SHA256withRSA"))
                    },
                    {
                            "Sample signature".getBytes(), "wso2carbon", mechanismResolver
                            .resolveMechanism(new MechanismDataHolder(SIGN_MODE, "SHA256withRSAandMGF1"))
                    },
                    {
                            "Sample signature".getBytes(), "wso2carbon", mechanismResolver
                            .resolveMechanism(new MechanismDataHolder(SIGN_MODE, "SHA1"))
                    },
                    {
                            new byte[1000], "wso2carbon", Mechanism.get(PKCS11Constants.CKM_RSA_PKCS)
                    }
            };
        } catch (CryptoException e) {
            System.out.println("Error occurred while generating sample data : " + e.getMessage());
            return null;
        }
    }

    @DataProvider(name = "sampleVerifyDataProvider")
    public Object[][] getSampleVerifyData() {

        try {
            return new Object[][]{
                    {
                            "Sample Data to be signed".getBytes(), "wso2carbon",
                            mechanismResolver.resolveMechanism(new MechanismDataHolder(SIGN_MODE,
                                    "SHA512withRSAandMGF1")), signatures.get(0), true
                    },
                    {
                            "".getBytes(), "wso2carbon", mechanismResolver
                            .resolveMechanism(new MechanismDataHolder(SIGN_MODE,
                            "SHA256withRSA")), signatures.get(1), true
                    },
                    {
                            "Sample signature".getBytes(), "wso2carbon", mechanismResolver
                            .resolveMechanism(new MechanismDataHolder(SIGN_MODE,
                            "SHA256withRSAandMGF1")), signatures.get(2), true
                    },
                    {
                            "Sample signature".getBytes(), "wso2carbon",
                            Mechanism.get(PKCS11Constants.CKM_RSA_PKCS), new byte[16], false
                    },
                    {
                            "Sample signature2".getBytes(), "wso2carbon", mechanismResolver
                            .resolveMechanism(new MechanismDataHolder(SIGN_MODE,
                            "SHA256withRSAandMGF1")), signatures.get(2), false
                    }
            };
        } catch (CryptoException e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    protected PrivateKey getPrivateKey(String keyAlias) {

        PrivateKey privateKeyTemplate = new PrivateKey();
        privateKeyTemplate.getLabel().setCharArrayValue(keyAlias.toCharArray());
        privateKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PRIVATE_KEY);
        try {
            return (PrivateKey) keyHandler.retrieveKey(privateKeyTemplate);
        } catch (CryptoException e) {
            System.out.println("Error occurred when retrieving private key " + keyAlias + " " + e.getMessage());
            return null;
        }
    }

    protected PublicKey getPublicKey(String keyAlias) {

        PublicKey publicKeyTemplate = new PublicKey();
        publicKeyTemplate.getLabel().setCharArrayValue(keyAlias.toCharArray());
        publicKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PUBLIC_KEY);
        try {
            return (PublicKey) keyHandler.retrieveKey(publicKeyTemplate);
        } catch (CryptoException e) {
            System.out.println("Error occurred when retrieving public key " + keyAlias + " : " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
}
