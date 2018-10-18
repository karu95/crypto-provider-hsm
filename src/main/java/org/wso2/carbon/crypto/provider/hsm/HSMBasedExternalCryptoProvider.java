package org.wso2.carbon.crypto.provider.hsm;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.objects.Certificate;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
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
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.MechanismDataHolder;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.MechanismResolver;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.SessionHandler;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;

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

    public HSMBasedExternalCryptoProvider(ServerConfigurationService serverConfigurationService)
            throws CryptoException {

        sessionHandler = SessionHandler.getDefaultSessionHandler(serverConfigurationService);
        this.serverConfigurationService = serverConfigurationService;
        mechanismResolver = MechanismResolver.getInstance();
    }

    @Override
    public byte[] sign(byte[] data, String algorithm, String javaSecurityAPIProvider, CryptoContext cryptoContext,
                       PrivateKeyInfo privateKeyInfo) throws CryptoException {

        failIfMethodParametersInvalid(algorithm);

        PrivateKey privateKeyTemplate = new PrivateKey();
        privateKeyTemplate.getLabel().setCharArrayValue(privateKeyInfo.getKeyAlias().toCharArray());
        privateKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PRIVATE_KEY);
        PrivateKey signingKey = (PrivateKey) retrieveKey(privateKeyTemplate);
        Mechanism signMechanism = mechanismResolver.resolveMechanism(new MechanismDataHolder(SIGN_MODE, algorithm));
        Session session = initiateSession();
        SignatureHandler signatureHandler = new SignatureHandler(session);
        try {
            return signatureHandler.sign(data, signingKey, signMechanism);
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, String algorithm, String javaSecurityAPIProvider,
                          CryptoContext cryptoContext, PrivateKeyInfo privateKeyInfo) throws CryptoException {

        failIfMethodParametersInvalid(algorithm);

        PrivateKey privateKeyTemplate = new PrivateKey();
        privateKeyTemplate.getLabel().setCharArrayValue(privateKeyInfo.getKeyAlias().toCharArray());
        privateKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PRIVATE_KEY);
        PrivateKey decryptionKey = (PrivateKey) retrieveKey(privateKeyTemplate);
        Mechanism decryptionMechanism = mechanismResolver.resolveMechanism(
                new MechanismDataHolder(DECRYPT_MODE, algorithm));
        Session session = initiateSession();
        Cipher cipher = new Cipher(session);
        try {
            return cipher.decrypt(ciphertext, decryptionKey, decryptionMechanism);
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    @Override
    public byte[] encrypt(byte[] data, String algorithm, String javaSecurityAPIProvider,
                          CryptoContext cryptoContext, CertificateInfo certificateInfo) throws CryptoException {

        failIfMethodParametersInvalid(algorithm);
        X509PublicKeyCertificate certificate = (X509PublicKeyCertificate)
                retrieveCertificate(certificateInfo.getCertificateAlias());
        PublicKey publicKeyTemplate = new PublicKey();
        publicKeyTemplate.getSubject().setByteArrayValue(certificate.getSubject().getByteArrayValue());
        publicKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PUBLIC_KEY);
        PublicKey encryptionKey = (PublicKey) retrieveKey(publicKeyTemplate);
        Mechanism encryptionMechanism = mechanismResolver.resolveMechanism(
                new MechanismDataHolder(ENCRYPT_MODE, algorithm));
        Session session = initiateSession();
        Cipher cipher = new Cipher(session);
        try {
            return cipher.encrypt(data, encryptionKey, encryptionMechanism);
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    @Override
    public boolean verifySignature(byte[] data, byte[] signature, String algorithm, String javaSecurityAPIProvider,
                                   CryptoContext cryptoContext, CertificateInfo certificateInfo) throws CryptoException {

        failIfMethodParametersInvalid(algorithm);

        X509PublicKeyCertificate certificate = (X509PublicKeyCertificate)
                retrieveCertificate(certificateInfo.getCertificateAlias());
        PublicKey publicKeyTemplate = new PublicKey();
        publicKeyTemplate.getSubject().setByteArrayValue(certificate.getValue().getByteArrayValue());
        publicKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PUBLIC_KEY);
        PublicKey verificationKey = (PublicKey) retrieveKey(publicKeyTemplate);
        Mechanism verifyMechanism = mechanismResolver.resolveMechanism(new MechanismDataHolder(VERIFY_MODE, algorithm));
        Session session = initiateSession();
        SignatureHandler signatureHandler = new SignatureHandler(session);
        try {
            return signatureHandler.verify(data, signature, verificationKey, verifyMechanism);
        } finally {
            sessionHandler.closeSession(session);
        }
    }

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
            }
            return null;
        } catch (CertificateException e) {
            String errorMessage = String.format("Error occurred while generating X.509 certificate from the " +
                    "retrieved certificate from the HSM.");
            throw new CryptoException(errorMessage, e);
        }
    }

    @Override
    public java.security.PrivateKey getPrivateKey(CryptoContext cryptoContext,
                                                  PrivateKeyInfo privateKeyInfo) throws CryptoException {

        failIfContextInformationIsMissing(cryptoContext);

        java.security.PrivateKey privateKey = null;
        PrivateKey privateKeyTemplate = new PrivateKey();
        privateKeyTemplate.getLabel().setCharArrayValue(privateKeyInfo.getKeyAlias().toCharArray());
        privateKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PRIVATE_KEY);
        PrivateKey retrievedKey = (PrivateKey) retrieveKey(privateKeyTemplate);
        String keyGenerationAlgorithm = null;
        try {
            if (!retrievedKey.getSensitive().getBooleanValue() && retrievedKey.getExtractable().getBooleanValue()) {
                if (retrievedKey instanceof RSAPrivateKey) {
                    RSAPrivateKey retrievedRSAKey = (RSAPrivateKey) retrievedKey;
                    BigInteger privateExponent = new BigInteger(retrievedRSAKey.
                            getPrivateExponent().getByteArrayValue());
                    BigInteger modulus = new BigInteger(retrievedRSAKey.getModulus().getByteArrayValue());
                    keyGenerationAlgorithm = "RSA";
                    privateKey = KeyFactory.getInstance(keyGenerationAlgorithm).generatePrivate(new
                            RSAPrivateKeySpec(modulus, privateExponent));
                }
            } else {
                throw new CryptoException("Requested private key is not extractable.");
            }
        } catch (InvalidKeySpecException e) {
            String errorMessage = String.format("Provided key specification is invalid for key alias '%s'",
                    privateKeyInfo.getKeyAlias());
            throw new CryptoException(errorMessage, e);
        } catch (NoSuchAlgorithmException e) {
            String errorMessage = String.format("Invalid key generation algorithm '%s'.", keyGenerationAlgorithm);
            throw new CryptoException(errorMessage, e);
        }
        return privateKey;
    }

    @Override
    public HybridEncryptionOutput hybridEncrypt(HybridEncryptionInput hybridEncryptionInput, String symmetricAlgorithm, String asymmetricAlgorithm,
                                                String javaSecurityProvider, CryptoContext cryptoContext,
                                                CertificateInfo certificateInfo) throws CryptoException {

        return null;
    }

    @Override
    public byte[] hybridDecrypt(HybridEncryptionOutput hybridDecryptionInput, String symmetricAlgorithm, String asymmetricAlgorithm,
                                String javaSecurityProvider, CryptoContext cryptoContext,
                                PrivateKeyInfo privateKeyInfo) throws CryptoException {

        return new byte[0];
    }

    protected Session initiateSession() throws CryptoException {

        return sessionHandler.initiateSession(
                Integer.parseInt(serverConfigurationService.getFirstProperty(EXTERNAL_PROVIDER_SLOT_PROPERTY_PATH)),
                false);
    }

    protected void failIfContextInformationIsMissing(CryptoContext cryptoContext) throws CryptoException {

        if (cryptoContext.getTenantId() == 0 || StringUtils.isBlank(cryptoContext.getTenantDomain())) {
            throw new CryptoException("Tenant information is missing in the crypto context.");
        }
    }

    protected void failIfMethodParametersInvalid(String algorithm) throws CryptoException {

        if (!(algorithm != null && MechanismResolver.getMechanisms().containsKey(algorithm))) {
            String errorMessage = String.format("Requested algorithm '%s' is not valid/supported by the " +
                    "provider '%s'.", algorithm);
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new CryptoException(errorMessage);
        }
    }

    protected Key retrieveKey(Key keyTemplate) throws CryptoException {

        Session session = initiateSession();
        KeyHandler keyHandler = new KeyHandler(session);
        try {
            return (Key) keyHandler.retrieveKey(keyTemplate);
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    protected Certificate retrieveCertificate(String label) throws CryptoException {

        Certificate certificateTemplate = new Certificate();
        certificateTemplate.getLabel().setCharArrayValue(label.toCharArray());
        certificateTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_CERTIFICATE);
        Session session = initiateSession();
        CertificateHandler certificateHandler = new CertificateHandler(session);
        try {
            return (Certificate) certificateHandler.getCertificate(certificateTemplate);
        } finally {
            sessionHandler.closeSession(session);
        }
    }
}
