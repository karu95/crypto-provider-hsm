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

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.Certificate;
import iaik.pkcs.pkcs11.objects.DES2SecretKey;
import iaik.pkcs.pkcs11.objects.DES3SecretKey;
import iaik.pkcs.pkcs11.objects.DESSecretKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.SecretKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.parameters.GcmParameters;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.parameters.Parameters;
import iaik.pkcs.pkcs11.wrapper.CK_GCM_PARAMS;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.api.CertificateInfo;
import org.wso2.carbon.crypto.api.CryptoContext;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.api.ExternalCryptoProvider;
import org.wso2.carbon.crypto.api.HybridEncryptionInput;
import org.wso2.carbon.crypto.api.HybridEncryptionOutput;
import org.wso2.carbon.crypto.api.PrivateKeyInfo;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.objecthandlers.CertificateHandler;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.objecthandlers.KeyHandler;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.operators.Cipher;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.operators.SignatureHandler;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.KeyTemplateGenerator;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.MechanismDataHolder;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.MechanismResolver;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.SessionHandler;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import static org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.CryptoConstants.DECRYPT_MODE;
import static org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.CryptoConstants.ENCRYPT_MODE;
import static org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.CryptoConstants.SIGN_MODE;
import static org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.CryptoConstants.VERIFY_MODE;

/**
 * Implementation of {@link ExternalCryptoProvider} to provide cryptographic operations using Hardware Security Modules.
 */
public class HSMBasedExternalCryptoProvider implements ExternalCryptoProvider {

    private static final String EXTERNAL_PROVIDER_SLOT_PROPERTY_PATH =
            "CryptoService.HSMBasedCryptoProviderConfig.ExternalProvider.ExternalProviderSlotID";

    private static Log log = LogFactory.getLog(HSMBasedExternalCryptoProvider.class);

    private ServerConfigurationService serverConfigurationService;
    private SessionHandler sessionHandler;
    private MechanismResolver mechanismResolver;

    /**
     * Constructor of {@link HSMBasedExternalCryptoProvider}.
     * Sets default {@link SessionHandler}, {@link MechanismResolver} for External provider.
     *
     * @param serverConfigurationService carbon.xml configuration is provided using this service.
     * @throws CryptoException If something unexpected happens during instantiating the External Provider.
     */
    public HSMBasedExternalCryptoProvider(ServerConfigurationService serverConfigurationService)
            throws CryptoException {

        sessionHandler = SessionHandler.getDefaultSessionHandler(serverConfigurationService);
        this.serverConfigurationService = serverConfigurationService;
        mechanismResolver = MechanismResolver.getInstance();
    }

    /**
     * Computes and returns the signature of given data, using the underlying HSM device.
     * Private key is retrieved from the HSM device.
     *
     * @param data                    The data whose signature is calculated.
     * @param algorithm               The signature + hashing algorithm to be used in signing.
     * @param javaSecurityAPIProvider The Java Security API provider.
     * @param cryptoContext           The context information needed for signing.
     * @param privateKeyInfo          Information about the private key.
     * @return The signature
     * @throws CryptoException If something unexpected happens during the signing operation.
     */
    @Override
    public byte[] sign(byte[] data, String algorithm, String javaSecurityAPIProvider, CryptoContext cryptoContext,
                       PrivateKeyInfo privateKeyInfo) throws CryptoException {

        failIfMethodParametersInvalid(algorithm);

        PrivateKey privateKeyTemplate = new PrivateKey();
        privateKeyTemplate.getLabel().setCharArrayValue(privateKeyInfo.getKeyAlias().toCharArray());
        privateKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PRIVATE_KEY);
        Mechanism signMechanism = mechanismResolver.resolveMechanism(new MechanismDataHolder(SIGN_MODE, algorithm));
        Session session = initiateSession();
        PrivateKey signingKey = (PrivateKey) retrieveKey(privateKeyTemplate, session);
        SignatureHandler signatureHandler = new SignatureHandler(session);
        try {
            return signatureHandler.sign(data, signingKey, signMechanism);
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    /**
     * Computes and returns the cleartext of the given cipher text using the underlying HSM device.
     * Assumes that keys are stored in the underlying HSM device.
     *
     * @param ciphertext              The ciphertext to be decrypted.
     * @param algorithm               The encryption / decryption algorithm
     * @param javaSecurityAPIProvider The Java Security API provider.
     * @param cryptoContext           The context information needed for signing.
     * @param privateKeyInfo          Information about the private key.
     * @return The cleartext
     * @throws CryptoException If something unexpected happens during the decryption operation.
     */
    @Override
    public byte[] decrypt(byte[] ciphertext, String algorithm, String javaSecurityAPIProvider,
                          CryptoContext cryptoContext, PrivateKeyInfo privateKeyInfo) throws CryptoException {

        failIfMethodParametersInvalid(algorithm);
        PrivateKey privateKeyTemplate = new PrivateKey();
        privateKeyTemplate.getLabel().setCharArrayValue(privateKeyInfo.getKeyAlias().toCharArray());
        privateKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PRIVATE_KEY);
        Mechanism decryptionMechanism = mechanismResolver.resolveMechanism(
                new MechanismDataHolder(DECRYPT_MODE, algorithm));
        Session session = initiateSession();
        PrivateKey decryptionKey = (PrivateKey) retrieveKey(privateKeyTemplate, session);
        Cipher cipher = new Cipher(session);
        try {
            return cipher.decrypt(ciphertext, decryptionKey, decryptionMechanism);
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    /**
     * Computes and returns the cipher text of the given cleartext using the underlying HSM device.
     * Public key is retrieved from the underlying HSM device.
     *
     * @param data                    The cleartext to be encrypted.
     * @param algorithm               The signature + hashing algorithm to be used in signing.
     * @param javaSecurityAPIProvider The Java Security API provider.
     * @param cryptoContext           The context information which was used to find discovery information about the
     *                                certificate
     *                                of the external entity.
     * @param certificateInfo         The information which is needed to retrieve the certificate.
     *                                If this information is not sufficient the {@link CryptoContext} will be used to
     *                                get more information.
     * @return The cleartext
     * @throws CryptoException If something unexpected happens during the encryption operation.
     */
    @Override
    public byte[] encrypt(byte[] data, String algorithm, String javaSecurityAPIProvider,
                          CryptoContext cryptoContext, CertificateInfo certificateInfo) throws CryptoException {

        failIfMethodParametersInvalid(algorithm);
        PublicKey publicKeyTemplate = new PublicKey();
        publicKeyTemplate.getLabel().setCharArrayValue(certificateInfo.getCertificateAlias().toCharArray());
        publicKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PUBLIC_KEY);
        Mechanism encryptionMechanism = mechanismResolver.resolveMechanism(
                new MechanismDataHolder(ENCRYPT_MODE, algorithm));
        Session session = initiateSession();
        PublicKey encryptionKey = (PublicKey) retrieveKey(publicKeyTemplate, session);
        Cipher cipher = new Cipher(session);
        try {
            return cipher.encrypt(data, encryptionKey, encryptionMechanism);
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    /**
     * Verifies whether given signature of the given data was generated by a trusted external party.
     * Signature verification is carried out using the underlying HSM device.
     * Public key is retrieved from the HSM device.
     *
     * @param data                    The data which was the signature generated on.
     * @param signature               The signature bytes of data.
     * @param algorithm               The signature + hashing algorithm to be used in signing.
     * @param javaSecurityAPIProvider The Java Security API provider.
     * @param cryptoContext           The context information which is needed to discover the public key of
     *                                the external entity.
     * @param certificateInfo         The information which is needed to retrieve the certificate.
     *                                If this information is not sufficient the {@link CryptoContext} will be used to
     *                                get more information.
     * @return true if signature can be verified, false otherwise.
     * @throws CryptoException If something unexpected happens during the signature verification.
     */
    @Override
    public boolean verifySignature(byte[] data, byte[] signature, String algorithm, String javaSecurityAPIProvider,
                                   CryptoContext cryptoContext, CertificateInfo certificateInfo) throws CryptoException {

        failIfMethodParametersInvalid(algorithm);
        PublicKey publicKeyTemplate = new PublicKey();
        publicKeyTemplate.getLabel().setCharArrayValue(certificateInfo.getCertificateAlias().toCharArray());
        publicKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PUBLIC_KEY);
        Mechanism verifyMechanism = mechanismResolver.resolveMechanism(new MechanismDataHolder(VERIFY_MODE, algorithm));
        Session session = initiateSession();
        PublicKey verificationKey = (PublicKey) retrieveKey(publicKeyTemplate, session);
        SignatureHandler signatureHandler = new SignatureHandler(session);
        try {
            return signatureHandler.verify(data, signature, verificationKey, verifyMechanism);
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    /**
     * Returns the {@link java.security.cert.Certificate} based on the given {@link CryptoContext}
     * Certificate is retrieved from the underlying HSM device.
     *
     * @param cryptoContext   The context information which is used to discover the public key of the external entity.
     * @param certificateInfo The information which is needed to retrieve the certificate.
     *                        If this information is not sufficient the {@link CryptoContext} will be used to
     *                        get more information.
     * @return The {@link java.security.cert.Certificate} relates with the given context.
     * @throws CryptoException If something unexpected happens during certificate discovery.
     */
    @Override
    public java.security.cert.Certificate getCertificate(CryptoContext cryptoContext,
                                                         CertificateInfo certificateInfo) throws CryptoException {

        failIfContextInformationIsMissing(cryptoContext);
        Certificate retrievedCertificate = retrieveCertificate(certificateInfo.getCertificateAlias());
        try {
            if (retrievedCertificate instanceof X509PublicKeyCertificate) {
                byte[] x509Certificate = ((X509PublicKeyCertificate) retrievedCertificate)
                        .getValue().getByteArrayValue();
                return CertificateFactory.getInstance("X.509").generateCertificate(
                        new ByteArrayInputStream(x509Certificate));
            } else {
                String errorMessage = String.format("Retrieved %s certificate format is not supported by the HSM " +
                        "based crypto provider.", certificateInfo.getCertificateAlias());
                throw new CryptoException(errorMessage);
            }
        } catch (CertificateException e) {
            String errorMessage = String.format("Error occurred while generating X.509 certificate from the " +
                    "retrieved certificate from the HSM.");
            throw new CryptoException(errorMessage, e);
        }
    }

    /**
     * Returns the {@link java.security.PrivateKey} based on the given {@link CryptoContext}
     * This certificate is retrieved from the underlying HSM device.
     * This implementation supports only RSA private keys at the moment.
     *
     * @param cryptoContext  The context information which is used to discover the applicable private key.
     * @param privateKeyInfo The information which is needed to retrieve the private key.
     *                       If this information is not sufficient, the {@link CryptoContext} will be used to
     *                       get more information.
     * @return The {@link java.security.PrivateKey} relates with the given context.
     * @throws CryptoException If something unexpected happens during private key discovery.
     */
    @Override
    public java.security.PrivateKey getPrivateKey(CryptoContext cryptoContext,
                                                  PrivateKeyInfo privateKeyInfo) throws CryptoException {

        failIfContextInformationIsMissing(cryptoContext);
        PrivateKey privateKeyTemplate = new PrivateKey();
        privateKeyTemplate.getLabel().setCharArrayValue(privateKeyInfo.getKeyAlias().toCharArray());
        privateKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PRIVATE_KEY);
        Session session = initiateSession();
        PrivateKey retrievedKey;
        try {
            retrievedKey = (PrivateKey) retrieveKey(privateKeyTemplate, session);
        } finally {
            sessionHandler.closeSession(session);
        }
        String keyGenerationAlgorithm = null;
        try {
            if (!retrievedKey.getSensitive().getBooleanValue() && retrievedKey.getExtractable().getBooleanValue()) {
                if (retrievedKey instanceof RSAPrivateKey) {
                    RSAPrivateKey retrievedRSAKey = (RSAPrivateKey) retrievedKey;
                    BigInteger privateExponent = new BigInteger(retrievedRSAKey.
                            getPrivateExponent().getByteArrayValue());
                    BigInteger modulus = new BigInteger(retrievedRSAKey.getModulus().getByteArrayValue());
                    keyGenerationAlgorithm = "RSA";
                    return KeyFactory.getInstance(keyGenerationAlgorithm).generatePrivate(new
                            RSAPrivateKeySpec(modulus, privateExponent));
                } else {
                    String errorMessage = String.format("Retrieved private key %s is not an instance of RSAPrivateKey.",
                            privateKeyInfo.getKeyAlias());
                    throw new CryptoException(errorMessage);
                }
            } else {
                String errorMessage = String.format("Requested private key %s is not extractable.",
                        privateKeyInfo.getKeyAlias());
                throw new CryptoException(errorMessage);
            }
        } catch (InvalidKeySpecException e) {
            String errorMessage = String.format("Provided key specification is invalid for key alias '%s'",
                    privateKeyInfo.getKeyAlias());
            throw new CryptoException(errorMessage, e);
        } catch (NoSuchAlgorithmException e) {
            String errorMessage = String.format("Invalid key generation algorithm '%s'.", keyGenerationAlgorithm);
            throw new CryptoException(errorMessage, e);
        }
    }

    /**
     * Computes and returns the {@link HybridEncryptionOutput} based on provided {@link HybridEncryptionInput}
     * Hybrid encryption is carried out using the underlying HSM device.
     * Session object is created for symmetric key for decryption.
     *
     * @param hybridEncryptionInput Input data for hybrid encryption.*
     * @param symmetricAlgorithm    The symmetric encryption/decryption algorithm.
     * @param asymmetricAlgorithm   The asymmetric encryption/decryption algorithm.
     * @param javaSecurityProvider  The Java Security API provider. This value is discarded in this component.
     * @param cryptoContext         The context information which is used to discover the public key of the external entity.
     * @return {@link HybridEncryptionOutput} cipher text with required parameters
     * @throws CryptoException
     */
    @Override
    public HybridEncryptionOutput hybridEncrypt(HybridEncryptionInput hybridEncryptionInput, String symmetricAlgorithm,
                                                String asymmetricAlgorithm, String javaSecurityProvider,
                                                CryptoContext cryptoContext, CertificateInfo certificateInfo)
            throws CryptoException {

        MechanismDataHolder mechanismDataHolder = new MechanismDataHolder(ENCRYPT_MODE, symmetricAlgorithm,
                hybridEncryptionInput.getAuthData());
        Mechanism symmetricMechanism = mechanismResolver.resolveMechanism(mechanismDataHolder);
        Session session = initiateSession();
        byte[] encryptedData;
        SecretKey encryptionKey = getSymmetricKey(session, symmetricAlgorithm, null, true);
        try {
            Cipher cipher = new Cipher(session);
            encryptedData = cipher.encrypt(hybridEncryptionInput.getPlainData(), encryptionKey, symmetricMechanism);
        } finally {
            sessionHandler.closeSession(session);
        }
        byte[] encryptedKey;
        if (encryptionKey instanceof AESSecretKey) {
            encryptedKey = encrypt(((AESSecretKey) encryptionKey).getValue().getByteArrayValue(),
                    asymmetricAlgorithm, javaSecurityProvider, cryptoContext, certificateInfo);
        } else if (encryptionKey instanceof DESSecretKey) {
            encryptedKey = encrypt(((DESSecretKey) encryptionKey).getValue().getByteArrayValue(),
                    asymmetricAlgorithm, javaSecurityProvider, cryptoContext, certificateInfo);
        } else if (encryptionKey instanceof DES2SecretKey) {
            encryptedKey = encrypt(((DES2SecretKey) encryptionKey).getValue().getByteArrayValue(),
                    asymmetricAlgorithm, javaSecurityProvider, cryptoContext, certificateInfo);
        } else if (encryptionKey instanceof DES3SecretKey) {
            encryptedKey = encrypt(((DES3SecretKey) encryptionKey).getValue().getByteArrayValue(),
                    asymmetricAlgorithm, javaSecurityProvider, cryptoContext, certificateInfo);
        } else {
            String errorMessage = String.format("Symmetric encryption key instance '%s' provided for hybrid " +
                    "encryption is not supported by the provider", encryptionKey.getClass().getName());
            throw new CryptoException(errorMessage);
        }
        HybridEncryptionOutput hybridEncryptionOutput;
        Parameters paramObject = symmetricMechanism.getParameters();
        if (paramObject instanceof GcmParameters) {
            CK_GCM_PARAMS gcmParams = (CK_GCM_PARAMS) paramObject.getPKCS11ParamsObject();
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec((int) gcmParams.ulTagBits, gcmParams.pIv);
            int tagPos = encryptedData.length - (int) (gcmParams.ulTagBits) / 8;
            byte[] cipherData = subArray(encryptedData, 0, tagPos);
            byte[] authTag = subArray(encryptedData, tagPos, (int) (gcmParams.ulTagBits) / 8);
            hybridEncryptionOutput = new HybridEncryptionOutput(cipherData, encryptedKey, gcmParams.pAAD,
                    authTag, gcmParameterSpec);
        } else if (paramObject instanceof InitializationVectorParameters) {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(((InitializationVectorParameters)
                    paramObject).getInitializationVector());
            hybridEncryptionOutput = new HybridEncryptionOutput(encryptedData, encryptedKey, ivParameterSpec);
        } else {
            String errorMessage = String.format("Invalid / Unsupported parameter specification for '%s' symmetric " +
                    "encryption algorithm.", symmetricAlgorithm);
            throw new CryptoException(errorMessage);
        }
        return hybridEncryptionOutput;
    }

    /**
     * Computes and return clear data based on provided {@link HybridEncryptionOutput}
     * Hybrid decryption is carried out using the underlying HSM device.
     * Session object is created for symmetric key for decryption.
     *
     * @param hybridDecryptionInput {@link HybridEncryptionOutput} ciphered data with parameters.
     * @param symmetricAlgorithm    The symmetric encryption/decryption algorithm.
     * @param asymmetricAlgorithm   The asymmetric encryption/decryption algorithm.
     * @param javaSecurityProvider  The Java Security API provider.
     * @param cryptoContext         The context information which is used to discover the public key of the external entity.
     * @return the decrypted data
     * @throws CryptoException
     */
    @Override
    public byte[] hybridDecrypt(HybridEncryptionOutput hybridDecryptionInput, String symmetricAlgorithm,
                                String asymmetricAlgorithm, String javaSecurityProvider, CryptoContext cryptoContext,
                                PrivateKeyInfo privateKeyInfo) throws CryptoException {

        byte[] decryptionKeyValue = decrypt(hybridDecryptionInput.getEncryptedSymmetricKey(), asymmetricAlgorithm,
                javaSecurityProvider, cryptoContext, privateKeyInfo);
        MechanismDataHolder mechanismDataHolder = new MechanismDataHolder(DECRYPT_MODE, symmetricAlgorithm,
                hybridDecryptionInput.getParameterSpec(), hybridDecryptionInput.getAuthData());
        Mechanism decryptionMechanism = mechanismResolver.resolveMechanism(mechanismDataHolder);
        Session session = initiateSession();
        try {
            SecretKey decryptionKey = getSymmetricKey(session, symmetricAlgorithm, decryptionKeyValue, false);
            Cipher cipher = new Cipher(session);
            if (hybridDecryptionInput.getAuthTag() != null) {
                try {
                    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                    outputStream.write(hybridDecryptionInput.getCipherData());
                    outputStream.write(hybridDecryptionInput.getAuthTag());
                    return cipher.decrypt(outputStream.toByteArray(), decryptionKey, decryptionMechanism);
                } catch (IOException e) {
                    String errorMessage = String.format("Error occurred while decrypting hybrid encrypted data.");
                    throw new CryptoException(errorMessage, e);
                }
            } else {
                return cipher.decrypt(hybridDecryptionInput.getCipherData(), decryptionKey, decryptionMechanism);
            }
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    protected Session initiateSession() throws CryptoException {

        return sessionHandler.initiateSession(
                Integer.parseInt(serverConfigurationService.getFirstProperty(EXTERNAL_PROVIDER_SLOT_PROPERTY_PATH)),
                false);
    }

    protected void failIfContextInformationIsMissing(CryptoContext cryptoContext) throws CryptoException {

        if (cryptoContext == null || cryptoContext.getTenantId() == 0 ||
                StringUtils.isBlank(cryptoContext.getTenantDomain())) {
            throw new CryptoException("Tenant information is missing in the crypto context.");
        }
    }

    protected void failIfMethodParametersInvalid(String algorithm) throws CryptoException {

        if (!(algorithm != null && MechanismResolver.getSupportedMechanisms().containsKey(algorithm))) {
            String errorMessage = String.format("Requested algorithm '%s' is not valid/supported.", algorithm);
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new CryptoException(errorMessage);
        }
    }

    protected Key retrieveKey(Key keyTemplate, Session session) throws CryptoException {

        KeyHandler keyHandler = new KeyHandler(session);
        return keyHandler.retrieveKey(keyTemplate);
    }

    protected Certificate retrieveCertificate(String label) throws CryptoException {

        Certificate certificateTemplate = new Certificate();
        certificateTemplate.getLabel().setCharArrayValue(label.toCharArray());
        certificateTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_CERTIFICATE);
        Session session = initiateSession();
        CertificateHandler certificateHandler = new CertificateHandler(session);
        try {
            return certificateHandler.getCertificate(certificateTemplate);
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    protected SecretKey getSymmetricKey(Session session, String algorithm, byte[] value,
                                        boolean encryptMode) throws CryptoException {

        String[] keySpecification = algorithm.split("/")[0].split("_");
        String keyType = keySpecification[0];
        String errorMessage = String.format("Requested key generation is not supported for '%s' " +
                "algorithm", algorithm);
        SecretKey secretKeyTemplate;
        if (encryptMode) {
            if (keyType.equals("AES")) {
                long keyLength = 32L;
                if (keySpecification.length > 1) {
                    keyLength = Long.parseLong(keySpecification[1]) / 8;
                }
                secretKeyTemplate = KeyTemplateGenerator.generateAESKeyTemplate();
                ((AESSecretKey) secretKeyTemplate).getValueLen().setLongValue(keyLength);
            } else if (keyType.equals("DES")) {
                secretKeyTemplate = KeyTemplateGenerator.generateDESKeyTemplate();
            } else if (keyType.equals("DES2")) {
                secretKeyTemplate = KeyTemplateGenerator.generateDES2KeyTemplate();
            } else if (keyType.equals("3DES") || keyType.equals("DESede")) {
                secretKeyTemplate = KeyTemplateGenerator.generateDES3KeyTemplate();
            } else {
                throw new CryptoException(errorMessage);
            }
        } else {
            if (keyType.equals("AES")) {
                secretKeyTemplate = KeyTemplateGenerator.generateAESKeyTemplate();
                ((AESSecretKey) secretKeyTemplate).getValue().setValue(value);
            } else if (keyType.equals("DES")) {
                secretKeyTemplate = KeyTemplateGenerator.generateDESKeyTemplate();
                ((DESSecretKey) secretKeyTemplate).getValue().setValue(value);
            } else if (keyType.equals("DES2")) {
                secretKeyTemplate = KeyTemplateGenerator.generateDES2KeyTemplate();
                ((DES2SecretKey) secretKeyTemplate).getValue().setValue(value);
            } else if (keyType.equals("3DES") || keyType.equals("DESede")) {
                secretKeyTemplate = KeyTemplateGenerator.generateDES3KeyTemplate();
                ((DES3SecretKey) secretKeyTemplate).getValue().setValue(value);
            } else {
                throw new CryptoException(errorMessage);
            }
        }
        return generateKey(secretKeyTemplate, encryptMode, keyType, session);
    }

    protected SecretKey generateKey(SecretKey secretKeyTemplate, boolean encryptMode, String keyGenAlgo, Session
            session) throws CryptoException {

        KeyHandler keyHandler = new KeyHandler(session);
        if (encryptMode) {
            return keyHandler.generateSecretKey(secretKeyTemplate, mechanismResolver.resolveMechanism(
                    new MechanismDataHolder(ENCRYPT_MODE, keyGenAlgo)));
        } else {
            return keyHandler.getSecretKeyHandle(secretKeyTemplate);
        }
    }

    protected byte[] subArray(byte[] byteArray, int beginIndex, int length) {

        byte[] subArray = new byte[length];
        System.arraycopy(byteArray, beginIndex, subArray, 0, subArray.length);
        return subArray;
    }
}
