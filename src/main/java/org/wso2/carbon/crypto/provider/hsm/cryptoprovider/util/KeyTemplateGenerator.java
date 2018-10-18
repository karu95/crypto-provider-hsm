package org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util;

import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.DES2SecretKey;
import iaik.pkcs.pkcs11.objects.DES3SecretKey;
import iaik.pkcs.pkcs11.objects.DESSecretKey;
import iaik.pkcs.pkcs11.objects.SecretKey;


/**
 *
 */
public class KeyTemplateGenerator {

    public static AESSecretKey generateAESKeyTemplate(long valueLength) {

        AESSecretKey aesSecretKeyTemplate = new AESSecretKey();
        aesSecretKeyTemplate.getValueLen().setLongValue(valueLength);
        updateCommonAttributes(aesSecretKeyTemplate);
        return aesSecretKeyTemplate;
    }

    public static DESSecretKey generateDESKeyTemplate() {

        DESSecretKey desSecretKeyTemplate = new DESSecretKey();
        updateCommonAttributes(desSecretKeyTemplate);
        return desSecretKeyTemplate;
    }

    public static DES3SecretKey generateDES3KeyTemplate() {

        DES3SecretKey des3SecretKeyTemplate = new DES3SecretKey();
        updateCommonAttributes(des3SecretKeyTemplate);
        return des3SecretKeyTemplate;
    }

    public static DES2SecretKey generateDES2KeyTemplate() {

        DES2SecretKey des2SecretKeyTemplate = new DES2SecretKey();
        updateCommonAttributes(des2SecretKeyTemplate);
        return des2SecretKeyTemplate;
    }

    protected static void updateCommonAttributes(SecretKey keyTemplate) {

        keyTemplate.getExtractable().setBooleanValue(true);
        keyTemplate.getSensitive().setBooleanValue(false);
        keyTemplate.getToken().setBooleanValue(false);
    }
}
