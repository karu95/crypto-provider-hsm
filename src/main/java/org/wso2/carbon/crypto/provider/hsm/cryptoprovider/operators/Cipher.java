package org.wso2.carbon.crypto.provider.hsm.cryptoprovider.operators;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.exception.HSMCryptoException;

/**
 * This class is responsible for carrying out encrypt/decrypt operations.
 */
public class Cipher {

    private static Log log  = LogFactory.getLog(Cipher.class);

    private final Session session;

    /**
     * Constructor of a Cipher instance.
     */
    public Cipher(Session session) {
        this.session = session;
    }

    /**
     * Method to encrypt a given set of data using a given key.
     *
     * @param dataToBeEncrypted   : Byte array of data to be encrypted.
     * @param encryptionKey       : Key used for encryption.
     * @param encryptionMechanism : Encrypting mechanism.
     * @return : Byte array of encrypted data.
     * @throws CryptoException
     */
    public byte[] encrypt(byte[] dataToBeEncrypted,
                          Key encryptionKey, Mechanism encryptionMechanism) throws CryptoException {

        byte[] encryptedData = null;
        if (isEncryptDecryptMechanism(encryptionMechanism)) {
            try {
                session.encryptInit(encryptionMechanism, encryptionKey);
                encryptedData = session.encrypt(dataToBeEncrypted);
            } catch (TokenException e) {
                String errorMessage = String.format("Error occurred while encrypting data using algorithm '%s' .",
                        encryptionMechanism.getName());
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new HSMCryptoException(errorMessage, e);
            }
        } else {
            String errorMessage = String.format("Requested '%s' algorithm for data decryption is not a valid data " +
                    "encryption mechanism.", encryptionMechanism.getName());
            throw new CryptoException(errorMessage);
        }
        return encryptedData;
    }

    /**
     * Method to decrypt a given set of data using a given key.
     *
     * @param dataToBeDecrypted   : Byte array of data to be decrypted.
     * @param decryptionKey       : Key used for decryption.
     * @param decryptionMechanism : Decrypting mechanism.
     * @return : Byte array of decrypted data
     * @throws CryptoException
     */
    public byte[] decrypt(byte[] dataToBeDecrypted,
                          Key decryptionKey, Mechanism decryptionMechanism) throws CryptoException {

        byte[] decryptedData = null;
        if (isEncryptDecryptMechanism(decryptionMechanism)) {
            try {
                session.decryptInit(decryptionMechanism, decryptionKey);
                decryptedData = session.decrypt(dataToBeDecrypted);
            } catch (TokenException e) {
                String errorMessage = String.format("Error occurred while decrypting data using algorithm '%s'.",
                        decryptionMechanism.getName());
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new HSMCryptoException(errorMessage, e);
            }
        } else {
            String errorMessage = String.format("Requested '%s' algorithm for data decryption is not a valid data " +
                    "decryption mechanism.", decryptionMechanism.getName());
            throw new CryptoException(errorMessage);
        }
        return decryptedData;
    }

    private boolean isEncryptDecryptMechanism(Mechanism mechanism) {
        if (mechanism.isSingleOperationEncryptDecryptMechanism()
                || mechanism.isFullEncryptDecryptMechanism()) {
            return true;
        }
        if (mechanism.getMechanismCode() == PKCS11Constants.CKM_AES_GCM) {
            return true;
        }
        return false;
    }
}
