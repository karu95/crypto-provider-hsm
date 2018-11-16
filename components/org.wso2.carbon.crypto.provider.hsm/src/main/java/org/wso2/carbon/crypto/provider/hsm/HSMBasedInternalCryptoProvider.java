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

    private static final String HSM_BASED_INTERNAL_PROVIDER_KEY_ALIAS_PATH =
            "CryptoService.HSMBasedCryptoProviderConfig.InternalProvider.KeyAlias";

    private static Log log = LogFactory.getLog(HSMBasedInternalCryptoProvider.class);

    private String keyAlias;
    private SessionHandler sessionHandler;
    private MechanismResolver mechanismResolver;
    private SlotResolver slotResolver;

    /**
     * Constructor of HSMBasedInternalCryptoProvider. This is an asymmetric crypto provider which caters
     * internal cryptographic requirements using underlying HSM.
     *
     * @param serverConfigurationService : carbon.xml data as a configuration service.
     */
    public HSMBasedInternalCryptoProvider(ServerConfigurationService serverConfigurationService)
            throws CryptoException {

        this.keyAlias = serverConfigurationService.getFirstProperty(HSM_BASED_INTERNAL_PROVIDER_KEY_ALIAS_PATH);
        if (StringUtils.isBlank(keyAlias)) {
            throw new CryptoException("Key/Certificate aliases provided for internal crypto provider can't be empty.");
        }
        sessionHandler = SessionHandler.getDefaultSessionHandler(serverConfigurationService);
        mechanismResolver = MechanismResolver.getInstance();
        slotResolver = new DefaultSlotResolver(serverConfigurationService);
    }

    /**
     * Computes and returns the ciphertext of the given cleartext, using the underlying HSM device.
     *
     * @param cleartext               The cleartext to be encrypted.
     * @param algorithm               The encryption / decryption algorithm
     * @param javaSecurityAPIProvider The JCE provider used for encryption. For this implementation JCE provider
     *                                is discarded.
     * @return the ciphertext
     * @throws CryptoException
     */
    @Override
    public byte[] encrypt(byte[] cleartext, String algorithm, String javaSecurityAPIProvider) throws CryptoException {

        failIfMethodParametersInvalid(algorithm, cleartext);
        PublicKey publicKeyTemplate = new PublicKey();
        publicKeyTemplate.getLabel().setCharArrayValue(keyAlias.toCharArray());
        publicKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PUBLIC_KEY);
        Mechanism encryptionMechanism = mechanismResolver.resolveMechanism(
                new MechanismDataHolder(ENCRYPT_MODE, algorithm));
        Session session = initiateSession(slotResolver.resolveSlot(null));
        PublicKey encryptionKey = (PublicKey) retrieveKey(publicKeyTemplate, session);
        Cipher cipher = new Cipher(session);
        try {
            return cipher.encrypt(cleartext, encryptionKey, encryptionMechanism);
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    /**
     * Computes and returns the cleartext of the given ciphertext, using the underlying HSM device.
     *
     * @param ciphertext              The ciphertext to be decrypted.
     * @param algorithm               The encryption / decryption algorithm
     * @param javaSecurityAPIProvider The JCE provider used for decryption. For this implementation JCE provider
     *                                is discarded.
     * @return The cleartext
     * @throws CryptoException If something unexpected happens during the decryption operation.
     */
    @Override
    public byte[] decrypt(byte[] ciphertext, String algorithm, String javaSecurityAPIProvider) throws CryptoException {

        failIfMethodParametersInvalid(algorithm, ciphertext);

        PrivateKey privateKeyTemplate = new PrivateKey();
        privateKeyTemplate.getLabel().setCharArrayValue(keyAlias.toCharArray());
        privateKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PRIVATE_KEY);
        Mechanism decryptionMechanism = mechanismResolver.resolveMechanism(
                new MechanismDataHolder(DECRYPT_MODE, algorithm));
        Session session = initiateSession(slotResolver.resolveSlot(null));
        PrivateKey decryptionKey = (PrivateKey) retrieveKey(privateKeyTemplate, session);
        Cipher cipher = new Cipher(session);
        try {
            return cipher.decrypt(ciphertext, decryptionKey, decryptionMechanism);
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    protected Session initiateSession(SlotInfo slotInfo) throws CryptoException {

        return sessionHandler.initiateSession(slotInfo.getSlotID(), slotInfo.getPin(), false);
    }

    protected void failIfMethodParametersInvalid(String algorithm, byte[] data)
            throws CryptoException {

        if (!(algorithm != null && MechanismResolver.getSupportedMechanisms().containsKey(algorithm))) {
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

    protected Key retrieveKey(Key keyTemplate, Session session) throws CryptoException {

        KeyHandler keyHandler = new KeyHandler(session);
        return keyHandler.retrieveKey(keyTemplate);
    }
}
