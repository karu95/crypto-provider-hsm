package org.wso2.carbon.crypto.provider.hsm;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.api.InternalCryptoProvider;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.objecthandlers.KeyHandler;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.operators.Cipher;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.MechanismDataHolder;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.MechanismResolver;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.SessionHandler;

import static org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.CryptoConstants.DECRYPT_MODE;
import static org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.CryptoConstants.ENCRYPT_MODE;

/**
 * Implementation of {@link InternalCryptoProvider} to provide cryptographic operations using Hardware Security Modules.
 */
public class HSMBasedInternalCryptoProvider implements InternalCryptoProvider {

    private static Log log = LogFactory.getLog(HSMBasedInternalCryptoProvider.class);

    private static final String INTERNAL_PROVIDER_SLOT_PROPERTY_PATH =
            "CryptoService.HSMBasedCryptoProviderConfig.InternalProvider.InternalProviderSlotID";
    private static final String HSM_BASED_INTERNAL_PROVIDER_KEY_ALIAS_PATH =
            "CryptoService.HSMBasedCryptoProviderConfig.InternalProvider.InternalProviderKeyAlias";

    private ServerConfigurationService serverConfigurationService;
    private String keyAlias;
    private SessionHandler sessionHandler;
    private MechanismResolver mechanismResolver;

    /**
     * Constructor of HSMBasedInternalCryptoProvider. This is an asymmetric crypto provider.
     *
     * @param serverConfigurationService
     */
    public HSMBasedInternalCryptoProvider(ServerConfigurationService serverConfigurationService)
            throws CryptoException {

        this.serverConfigurationService = serverConfigurationService;
        this.keyAlias = serverConfigurationService.getFirstProperty(HSM_BASED_INTERNAL_PROVIDER_KEY_ALIAS_PATH);
        if (StringUtils.isBlank(keyAlias)) {
            throw new CryptoException();
        }
        sessionHandler = SessionHandler.getDefaultSessionHandler(serverConfigurationService);
        mechanismResolver = MechanismResolver.getInstance();
    }

    @Override
    public byte[] encrypt(byte[] cleartext, String algorithm, String javaSecurityAPIProvider) throws CryptoException {

        failIfMethodParametersInvalid(algorithm, cleartext);
        PublicKey publicKeyTemplate = new PublicKey();
        publicKeyTemplate.getLabel().setCharArrayValue(keyAlias.toCharArray());
        publicKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PUBLIC_KEY);
        PublicKey encryptionKey = (PublicKey) retrieveKey(publicKeyTemplate);
        Mechanism encryptionMechanism = mechanismResolver.resolveMechanism(
                new MechanismDataHolder(ENCRYPT_MODE, algorithm));
        Session session = initiateSession();
        Cipher cipher = new Cipher(session);
        try {
            return cipher.encrypt(cleartext, encryptionKey, encryptionMechanism);
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, String algorithm, String javaSecurityAPIProvider) throws CryptoException {

        failIfMethodParametersInvalid(algorithm , ciphertext);

        PrivateKey privateKeyTemplate = new PrivateKey();
        privateKeyTemplate.getLabel().setCharArrayValue(keyAlias.toCharArray());
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

    protected Session initiateSession() throws CryptoException {

        return sessionHandler.initiateSession(
                Integer.parseInt(serverConfigurationService.getFirstProperty(INTERNAL_PROVIDER_SLOT_PROPERTY_PATH)),
                false);
    }


    protected void failIfMethodParametersInvalid(String algorithm, byte[] data)
            throws CryptoException {

        if (!(algorithm != null && MechanismResolver.getMechanisms().containsKey(algorithm))) {
            String errorMessage = String.format("Requested algorithm '%s' is not valid/supported by the " +
                    "HSM based Crypto Provider.", algorithm);
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new CryptoException(errorMessage);
        }

        if (data == null || data.length == 0) {
            String errorMessage = String.format("Data sent for cryptographic operation is null/empty.");
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new CryptoException(errorMessage);
        }
    }

    protected Key retrieveKey(Key keyTemplate) throws CryptoException {

        Session session = initiateSession();
        KeyHandler keyHandler = new KeyHandler(session);
        Key retrievedKey;
        try {
            retrievedKey = (Key) keyHandler.retrieveKey(keyTemplate);
        } finally {
            sessionHandler.closeSession(session);
        }
        return retrievedKey;
    }
}
