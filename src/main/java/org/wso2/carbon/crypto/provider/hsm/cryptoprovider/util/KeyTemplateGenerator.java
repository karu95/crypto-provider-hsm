package org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util;

import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.DES2SecretKey;
import iaik.pkcs.pkcs11.objects.DES3SecretKey;
import iaik.pkcs.pkcs11.objects.DESSecretKey;
import iaik.pkcs.pkcs11.objects.SecretKey;


/**
 * This class generates symmetric key templates required for symmetric key generation.
 */
public class KeyTemplateGenerator {

    /**
     * Generates a {@link AESSecretKey} template with required attributes.
     *
     * @return {@link AESSecretKey} template.
     */
    public static AESSecretKey generateAESKeyTemplate() {

        AESSecretKey aesSecretKeyTemplate = new AESSecretKey();
        updateCommonAttributes(aesSecretKeyTemplate);
        return aesSecretKeyTemplate;
    }

    /**
     * Generates a {@link DESSecretKey} template with required attributes.
     *
     * @return {@link DESSecretKey} template.
     */
    public static DESSecretKey generateDESKeyTemplate() {

        DESSecretKey desSecretKeyTemplate = new DESSecretKey();
        updateCommonAttributes(desSecretKeyTemplate);
        return desSecretKeyTemplate;
    }

    /**
     * Generates a {@link DES3SecretKey} template with required attributes.
     *
     * @return {@link DES3SecretKey} template.
     */
    public static DES3SecretKey generateDES3KeyTemplate() {

        DES3SecretKey des3SecretKeyTemplate = new DES3SecretKey();
        updateCommonAttributes(des3SecretKeyTemplate);
        return des3SecretKeyTemplate;
    }

    /**
     * Generates a {@link DES2SecretKey} template with required attributes.
     *
     * @return {@link DES2SecretKey} template.
     */
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
