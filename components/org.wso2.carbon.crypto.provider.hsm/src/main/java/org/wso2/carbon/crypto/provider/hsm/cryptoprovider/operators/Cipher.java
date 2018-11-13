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

    private static Log log = LogFactory.getLog(Cipher.class);

    private final Session session;

    /**
     * Constructor of a Cipher instance.
     *
     * @param session : Session used for the encryption/decryption operation.
     */
    public Cipher(Session session) {

        this.session = session;
    }

    /**
     * Method to encrypt a given set of data using a given key.
     * Encryption is handled by the underlying HSM device.
     *
     * @param dataToBeEncrypted   : Byte array of data to be encrypted.
     * @param encryptionKey       : Key used for encryption.
     * @param encryptionMechanism : Encrypting mechanism.
     * @return : Byte array of encrypted data.
     * @throws CryptoException
     */
    public byte[] encrypt(byte[] dataToBeEncrypted,
                          Key encryptionKey, Mechanism encryptionMechanism) throws CryptoException {

        if (isEncryptDecryptMechanism(encryptionMechanism)) {
            try {
                session.encryptInit(encryptionMechanism, encryptionKey);
                return session.encrypt(dataToBeEncrypted);
            } catch (TokenException e) {
                String errorMessage = String.format("Error occurred while encrypting data using algorithm '%s' .",
                        encryptionMechanism.getName());
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new HSMCryptoException(errorMessage, e);
            }
        } else {
            String errorMessage = String.format("Requested '%s' algorithm for data encryption is not a valid data " +
                    "encryption mechanism.", encryptionMechanism.getName());
            throw new CryptoException(errorMessage);
        }
    }

    /**
     * Method to decrypt a given set of data using a given key.
     * Decryption is handled by the underlying HSM device.
     *
     * @param dataToBeDecrypted   : Byte array of data to be decrypted.
     * @param decryptionKey       : Key used for decryption.
     * @param decryptionMechanism : Decrypting mechanism.
     * @return : Byte array of decrypted data
     * @throws CryptoException
     */
    public byte[] decrypt(byte[] dataToBeDecrypted,
                          Key decryptionKey, Mechanism decryptionMechanism) throws CryptoException {

        if (isEncryptDecryptMechanism(decryptionMechanism)) {
            try {
                session.decryptInit(decryptionMechanism, decryptionKey);
                return session.decrypt(dataToBeDecrypted);
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
    }

    protected boolean isEncryptDecryptMechanism(Mechanism mechanism) {

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
