package org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.parameters.GcmParameters;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.parameters.RSAPkcsOaepParameters;
import iaik.pkcs.pkcs11.parameters.RSAPkcsPssParameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.wso2.carbon.crypto.api.CryptoException;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.HashMap;

import static org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.CryptoConstants.DECRYPT_MODE;
import static org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.CryptoConstants.ENCRYPT_MODE;

/**
 * This class is used to resolve JCE standard mechanism names to PKCS #11 mechanisms.
 */
public class MechanismResolver {

    private static MechanismResolver mechanismResolver;
    private static SecureRandom random = new SecureRandom();
    private static HashMap<String, Long> mechanisms = new HashMap<String, Long>() {{

        /*
         * Key generation mechanisms
         */
        put("AES", PKCS11Constants.CKM_AES_KEY_GEN);
        put("DES", PKCS11Constants.CKM_DES_KEY_GEN);
        put("DES2", PKCS11Constants.CKM_DES2_KEY_GEN);
        put("3DES", PKCS11Constants.CKM_DES3_KEY_GEN);
        put("DESede", PKCS11Constants.CKM_DES3_KEY_GEN);

        /*
         * Encrypt/Decrypt mechanisms
         */
        //DES mechanisms
        put("DES/CBC/NoPadding", PKCS11Constants.CKM_DES_CBC);
        put("DES/CBC/PKCS5Padding", PKCS11Constants.CKM_DES_CBC_PAD);
        put("DES/ECB/NoPadding", PKCS11Constants.CKM_DES_ECB);

        //DES3 mechanisms
        put("DESede/CBC/NoPadding", PKCS11Constants.CKM_DES3_CBC);
        put("3DES/CBC/NoPadding", PKCS11Constants.CKM_DES3_CBC);
        put("DESede/CBC/PKCS5Padding", PKCS11Constants.CKM_DES3_CBC_PAD);
        put("3DES/CBC/PKCS5Padding", PKCS11Constants.CKM_DES3_CBC_PAD);
        put("DESede/ECB/NoPadding", PKCS11Constants.CKM_DES3_ECB);
        put("3DES/ECB/NoPadding", PKCS11Constants.CKM_DES3_ECB);

        //AES mechanisms
        put("AES/CBC/NoPadding", PKCS11Constants.CKM_AES_CBC);
        put("AES_128/CBC/NoPadding", PKCS11Constants.CKM_AES_CBC);
        put("AES_192/CBC/NoPadding", PKCS11Constants.CKM_AES_CBC);
        put("AES_256/CBC/NoPadding", PKCS11Constants.CKM_AES_CBC);
        put("AES/CBC/PKCS5Padding", PKCS11Constants.CKM_AES_CBC_PAD);
        put("AES_128/CBC/PKCS5Padding", PKCS11Constants.CKM_AES_CBC_PAD);
        put("AES_192/CBC/PKCS5Padding", PKCS11Constants.CKM_AES_CBC_PAD);
        put("AES_256/CBC/PKCS5Padding", PKCS11Constants.CKM_AES_CBC_PAD);
        put("AES/ECB/NoPadding", PKCS11Constants.CKM_AES_ECB);
        put("AES_128/ECB/NoPadding", PKCS11Constants.CKM_AES_ECB);
        put("AES_192/ECB/NoPadding", PKCS11Constants.CKM_AES_ECB);
        put("AES_256/ECB/NoPadding", PKCS11Constants.CKM_AES_ECB);
        put("AES/CCM/NoPadding", PKCS11Constants.CKM_AES_CCM);
        put("AES_128/CCM/NoPadding", PKCS11Constants.CKM_AES_CCM);
        put("AES_192/CCM/NoPadding", PKCS11Constants.CKM_AES_CCM);
        put("AES_256/CCM/NoPadding", PKCS11Constants.CKM_AES_CCM);
        put("AES/GCM/NoPadding", PKCS11Constants.CKM_AES_GCM);
        put("AES_128/GCM/NoPadding", PKCS11Constants.CKM_AES_GCM);
        put("AES_192/GCM/NoPadding", PKCS11Constants.CKM_AES_GCM);
        put("AES_256/GCM/NoPadding", PKCS11Constants.CKM_AES_GCM);

        //RSA mechanisms
        put("RSA/ECB/OAEPwithMD5andMGF1Padding", PKCS11Constants.CKM_RSA_PKCS_OAEP);
        put("RSA/ECB/OAEPwithSHA1andMGF1Padding", PKCS11Constants.CKM_RSA_PKCS_OAEP);
        put("RSA/ECB/OAEPwithSHA224andMGF1Padding", PKCS11Constants.CKM_RSA_PKCS_OAEP);
        put("RSA/ECB/OAEPwithSHA256andMGF1Padding", PKCS11Constants.CKM_RSA_PKCS_OAEP);
        put("RSA/ECB/OAEPwithSHA384andMGF1Padding", PKCS11Constants.CKM_RSA_PKCS_OAEP);
        put("RSA/ECB/OAEPwithSHA512andMGF1Padding", PKCS11Constants.CKM_RSA_PKCS_OAEP);
        put("RSA/ECB/PKCS1Padding", PKCS11Constants.CKM_RSA_PKCS);
        put("RSA/ECB/NoPadding", PKCS11Constants.CKM_RSA_X_509);
        put("RSA/ECB/ISO9796Padding", PKCS11Constants.CKM_RSA_9796);

        //Blowfish mechanisms
        put("Blowfish/CBC/NoPadding", PKCS11Constants.CKM_BLOWFISH_CBC);
        put("Blowfish/CBC/PKCS5Padding", PKCS11Constants.CKM_BLOWFISH_CBC);

        /*
         * Sign/Verify mechanisms
         */
        //ECDSA sign/verify mechanisms
        put("NONEwithECDSA", PKCS11Constants.CKM_ECDSA);
        put("SHA1withECDSA", PKCS11Constants.CKM_ECDSA_SHA1);

        //RSA sign/verify mechanisms
        put("MD2withRSA", PKCS11Constants.CKM_MD2_RSA_PKCS);
        put("MD5withRSA", PKCS11Constants.CKM_MD5_RSA_PKCS);
        put("SHA1withRSA", PKCS11Constants.CKM_SHA1_RSA_PKCS);
        put("SHA256withRSA", PKCS11Constants.CKM_SHA256_RSA_PKCS);
        put("SHA384withRSA", PKCS11Constants.CKM_SHA384_RSA_PKCS);
        put("SHA512withRSA", PKCS11Constants.CKM_SHA512_RSA_PKCS);
        put("RipeMd128withRSA", PKCS11Constants.CKM_RIPEMD128_RSA_PKCS);
        put("RipeMd160withRSA", PKCS11Constants.CKM_RIPEMD160_RSA_PKCS);

        put("SHA1withRSAandMGF1", PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS);
        put("SHA256withRSAandMGF1", PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS);
        put("SHA384withRSAandMGF1", PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS);
        put("SHA512withRSAandMGF1", PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS);

        //DSA sign/verify mechanisms
        put("RawDSA", PKCS11Constants.CKM_DSA);
        put("SHA1withDSA", PKCS11Constants.CKM_DSA_SHA1);;

        /*
         * Digest mechanisms
         */
        put("SHA1", PKCS11Constants.CKM_SHA_1);
        put("SHA256", PKCS11Constants.CKM_SHA256);
        put("SHA384", PKCS11Constants.CKM_SHA384);
        put("SHA512", PKCS11Constants.CKM_SHA512);
        put("MD2", PKCS11Constants.CKM_MD2);
        put("MD5", PKCS11Constants.CKM_MD5);
        put("RipeMd128", PKCS11Constants.CKM_RIPEMD128);
        put("RipeMd160", PKCS11Constants.CKM_RIPEMD160);
    }};

    private static HashMap<Long, String> parameterRequiredMechanisms = new HashMap<Long, String>() {{
        put(PKCS11Constants.CKM_AES_CBC, "IV16");
        put(PKCS11Constants.CKM_AES_CBC_PAD, "IV16");
        put(PKCS11Constants.CKM_AES_GCM, "GCM");

        put(PKCS11Constants.CKM_RSA_PKCS_OAEP, "OAEP");

        put(PKCS11Constants.CKM_DES3_CBC, "IV8");
        put(PKCS11Constants.CKM_DES3_CBC_PAD, "IV8");

        put(PKCS11Constants.CKM_DES_CBC, "IV8");
        put(PKCS11Constants.CKM_DES_CBC_PAD, "IV8");

        put(PKCS11Constants.CKM_BLOWFISH_CBC, "IV8");

        put(PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS, "PSS");
        put(PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS, "PSS");
        put(PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS, "PSS");
        put(PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS, "PSS");
    }};

    /**
     * Singleton design pattern is used.
     *
     * @return {@link MechanismResolver} default instance.
     */
    public static MechanismResolver getInstance() {
        synchronized (MechanismResolver.class) {
            if (mechanismResolver == null) {
                mechanismResolver = new MechanismResolver();
            }
        }
        return mechanismResolver;
    }

    protected MechanismResolver() {
    }

    /**
     * Method to retrieve of mechanisms.
     *
     * @return HashMap of mechanisms.
     */
    public static HashMap<String, Long> getSupportedMechanisms() {
        return mechanisms;
    }

    /**
     * Method to resolve the PKCS #11 mechanism when JCE mechanism specification is given.
     *
     * @param mechanismDataHolder : Holds required data to resolve the mechanism with required parameters.
     * @return : Properly configured mechanism.
     */
    public Mechanism resolveMechanism(MechanismDataHolder mechanismDataHolder) throws CryptoException {

        Mechanism mechanism = null;
        if (mechanisms.containsKey(mechanismDataHolder.getJceMechanismSpecification())) {
            mechanism = Mechanism.get(mechanisms.get(mechanismDataHolder.getJceMechanismSpecification()));
            if (parameterRequiredMechanisms.containsKey(mechanism.getMechanismCode())) {
                resolveParameters(mechanism, mechanismDataHolder);
            }
        }
        return mechanism;
    }

    protected void resolveParameters(Mechanism mechanism, MechanismDataHolder mechanismDataHolder) throws CryptoException {

        String parameterSpec = parameterRequiredMechanisms.get(mechanism.getMechanismCode());
        if (parameterSpec.equals("OAEP")) {
            String[] specification = mechanismDataHolder.getJceMechanismSpecification().split("/");
            mechanism.setParameters(getOAEPParameters(specification[specification.length - 1]));
        } else if (parameterSpec.equals("PSS")) {
            mechanism.setParameters(getRSAPSSParameters(mechanismDataHolder.getJceMechanismSpecification()));
        } else if (parameterSpec.startsWith("IV")) {
            int ivSize = Integer.parseInt(parameterSpec.substring(2, parameterSpec.length()));
            mechanism.setParameters(getInitializationVectorParameters((IvParameterSpec) mechanismDataHolder
                    .getAlgorithmParameterSpec(), mechanismDataHolder.getOperatingMode(), ivSize));
        } else if (parameterSpec.startsWith("GCM")) {
            mechanism.setParameters(getGCMParameters((GCMParameterSpec) mechanismDataHolder.getAlgorithmParameterSpec(),
                    mechanismDataHolder.getOperatingMode(), 12, mechanismDataHolder.getAuthData()));
        }
    }

    protected RSAPkcsOaepParameters getOAEPParameters(String parameter) throws CryptoException {

        String[] specParams = parameter.split("with");
        String[] oaepParams = specParams[1].split("and");
        if (mechanisms.containsKey(oaepParams[0])) {
            return new RSAPkcsOaepParameters(Mechanism.get(mechanisms.get(oaepParams[0])), 1L,
                    PKCS11Constants.CKZ_DATA_SPECIFIED, null);
        } else {
            String errorMessage = String.format("Invalid '%s' OAEP parameter specification", parameter);
            throw new CryptoException(errorMessage);
        }
    }

    protected RSAPkcsPssParameters getRSAPSSParameters(String algorithmSpecification) throws CryptoException {

        if (algorithmSpecification.contains("SHA1")) {
            return new RSAPkcsPssParameters(Mechanism.get(mechanisms.get("SHA1")), 1L,
                    20L);
        } else if (algorithmSpecification.contains("SHA256")) {
            return new RSAPkcsPssParameters(Mechanism.get(mechanisms.get("SHA256")), 1L,
                    32L);
        } else if (algorithmSpecification.contains("SHA384")) {
            return new RSAPkcsPssParameters(Mechanism.get(mechanisms.get("SHA384")), 1L,
                    48L);
        } else if (algorithmSpecification.contains("SHA512")) {
            return new RSAPkcsPssParameters(Mechanism.get(mechanisms.get("SHA512")), 1L,
                    64L);
        } else {
            String errorMessage = String.format("Invalid '%s' algorithm specification", algorithmSpecification);
            throw new CryptoException(errorMessage);
        }
    }

    protected InitializationVectorParameters getInitializationVectorParameters(IvParameterSpec ivParameterSpec,
                                                                               int operatingMode, int ivSize) throws CryptoException {

        if (operatingMode == ENCRYPT_MODE) {
            return new InitializationVectorParameters(generateIV(ivSize));
        } else if (operatingMode == DECRYPT_MODE) {
            if (ivParameterSpec != null) {
                return new InitializationVectorParameters(ivParameterSpec.getIV());
            } else {
                String errorMessage = "Initialization vector parameters can't be null";
                throw new CryptoException(errorMessage);
            }
        } else {
            String errorMessage = "IV vectors are not defined for sign/verify operating modes.";
            throw new CryptoException(errorMessage);
        }
    }

    protected GcmParameters getGCMParameters(GCMParameterSpec gcmParameterSpec, int operatingMode, int ivSize,
                                             byte[] authData) throws CryptoException {

        if (operatingMode == ENCRYPT_MODE) {
            return new GcmParameters(generateIV(ivSize), authData, 128);
        } else if (operatingMode == DECRYPT_MODE) {
            if (gcmParameterSpec != null) {
                return new GcmParameters(gcmParameterSpec.getIV(), authData, gcmParameterSpec.getTLen());
            } else {
                String errorMessage = "GCM Parameters can't be null.";
                throw new CryptoException(errorMessage);
            }
        } else {
            String errorMessage = "Invalid mode of operation is requested.";
            throw new CryptoException(errorMessage);
        }
    }

    protected byte[] generateIV(int size) {
        byte[] iv = new byte[size];
        random.nextBytes(iv);
        return iv;
    }
}
