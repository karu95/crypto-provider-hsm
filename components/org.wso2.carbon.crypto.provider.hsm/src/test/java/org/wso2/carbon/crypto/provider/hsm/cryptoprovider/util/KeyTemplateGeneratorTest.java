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

import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.DES2SecretKey;
import iaik.pkcs.pkcs11.objects.DES3SecretKey;
import iaik.pkcs.pkcs11.objects.DESSecretKey;
import iaik.pkcs.pkcs11.objects.SecretKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.testng.Assert;
import org.testng.annotations.Test;

public class KeyTemplateGeneratorTest {

    @Test
    public void testGenerateAESKeyTemplate() {

        AESSecretKey secretKey = KeyTemplateGenerator.generateAESKeyTemplate();
        Assert.assertEquals((long) secretKey.getKeyType().getLongValue(), PKCS11Constants.CKK_AES);
        testCommonFeatures(secretKey);
    }

    @Test
    public void testGenerateDESKeyTemplate() {

        DESSecretKey secretKey = KeyTemplateGenerator.generateDESKeyTemplate();
        Assert.assertEquals((long) secretKey.getKeyType().getLongValue(), PKCS11Constants.CKK_DES);
        testCommonFeatures(secretKey);
    }

    @Test
    public void testGenerateDES2KeyTemplate() {

        DES2SecretKey secretKey = KeyTemplateGenerator.generateDES2KeyTemplate();
        Assert.assertEquals((long) secretKey.getKeyType().getLongValue(), PKCS11Constants.CKK_DES2);
        testCommonFeatures(secretKey);
    }

    @Test
    public void testGenerateDES3KeyTemplate() {

        DES3SecretKey secretKey = KeyTemplateGenerator.generateDES3KeyTemplate();
        Assert.assertEquals((long) secretKey.getKeyType().getLongValue(), PKCS11Constants.CKK_DES3);
        testCommonFeatures(secretKey);
    }

    private void testCommonFeatures(SecretKey secretKey) {

        Assert.assertEquals((long) secretKey.getObjectClass().getLongValue(), PKCS11Constants.CKO_SECRET_KEY);
        Assert.assertTrue(secretKey.getExtractable().getBooleanValue());
        Assert.assertFalse(secretKey.getSensitive().getBooleanValue());
        Assert.assertFalse(secretKey.getToken().getBooleanValue());
    }
}