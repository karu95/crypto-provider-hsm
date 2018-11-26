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

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.objects.Certificate;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.provider.hsm.TestUtil;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.SessionHandler;

public class CertificateHandlerTest {

    private Session session;
    private SessionHandler sessionHandler;
    private CertificateHandler certificateHandler;
    private String certificateNotInDevice = "notInsideHSM";

    @BeforeClass
    public void setUpClass() {

        sessionHandler = TestUtil.getSessionHandler();
    }

    @BeforeMethod
    public void setUp() {

        try {
            session = sessionHandler.initiateSession(0, null, false);
            certificateHandler = new CertificateHandler(session);
        } catch (CryptoException e) {
            System.out.println("Error occurred while initiating a session : " + e.getMessage());
        }
    }

    @Test(dataProvider = "sampleCertificateRetrievalData")
    public void testGetCertificate(Certificate certificateTemplate) {

        try {
            Certificate certificate = certificateHandler.getCertificate(certificateTemplate);
            Assert.assertEquals(certificate.getLabel().getCharArrayValue(),
                    certificateTemplate.getLabel().getCharArrayValue());
        } catch (CryptoException e) {
            if (certificateNotInDevice.equals(String.valueOf(certificateTemplate.getLabel().getCharArrayValue()))) {
                Assert.assertEquals(e.getMessage(), String.format("Requested certificate '%s' can't be found inside " +
                        "the HSM", String.valueOf(certificateTemplate.getLabel().getCharArrayValue())));
            }
            System.out.println(String.format("Error occurred while retrieving certificate '%s' : ",
                    String.valueOf(certificateTemplate.getLabel().getCharArrayValue())) + e.getMessage());
        }
    }

    @DataProvider(name = "sampleCertificateRetrievalData")
    public Object[][] getSampleCertificateData() {

        Certificate certificateTemplate1 = new Certificate();
        certificateTemplate1.getLabel().setCharArrayValue("wso2carbon".toCharArray());

        Certificate certificateTemplate2 = new Certificate();
        certificateTemplate2.getLabel().setCharArrayValue("5".toCharArray());

        Certificate certificateTemplate3 = new Certificate();
        certificateTemplate3.getLabel().setCharArrayValue("".toCharArray());

        Certificate certificateTemplate4 = new Certificate();
        certificateTemplate4.getLabel().setCharArrayValue(certificateNotInDevice.toCharArray());

        return new Object[][]{
                {
                        certificateTemplate1
                },
                {
                        certificateTemplate2
                },
                {
                        certificateTemplate3
                },
                {
                        certificateTemplate4
                }
        };
    }

    @AfterMethod
    public void tearDown() {

        try {
            sessionHandler.closeSession(session);
        } catch (CryptoException e) {
            System.out.println("Error occurred while closing the session : " + e.getMessage());
        }
    }
}