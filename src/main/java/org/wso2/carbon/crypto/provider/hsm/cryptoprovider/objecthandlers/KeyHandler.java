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

package org.wso2.carbon.crypto.provider.hsm.cryptoprovider.objecthandlers;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.SecretKey;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.exception.HSMCryptoException;

/**
 * This class is responsible to handle key related operations with HSM.
 */
public class KeyHandler {

    private static Log log = LogFactory.getLog(KeyHandler.class);

    private final Session session;

    /**
     * Constructor of key handler instance.
     *
     * @param session : Session associated to handle the key related operation.
     */
    public KeyHandler(Session session) {
        this.session = session;
    }

    /**
     * Method to retrieve key when template of the key is given.
     *
     * @param keyTemplate : Template of the key to be retrieved.
     * @return retrieved key
     * @throws TokenException
     */
    public Key retrieveKey(Key keyTemplate) throws CryptoException {

        Key key = null;
        try {
            session.findObjectsInit(keyTemplate);
            Object[] secretKeyArray = session.findObjects(1);
            if (secretKeyArray.length > 0) {
                key = (Key) secretKeyArray[0];
            }
        } catch (TokenException e) {
            String errorMessage = String.format("Error occurred while retrieving key for key alias '%s'.",
                    new String(keyTemplate.getLabel().getCharArrayValue()));
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new HSMCryptoException(errorMessage, e);
        }
        return key;
    }

    /**
     * Generates symmetric keys conforming to given secret key template.
     *
     * @param secretKeyTemplate : Template of the key that needs to be generated.
     * @param mechanism         : Key generation mechanism.
     * @return                  : Generated Key {@link SecretKey}
     * @throws HSMCryptoException
     */
    public SecretKey generateSecretKey(SecretKey secretKeyTemplate, Mechanism mechanism) throws HSMCryptoException {

        try {
            SecretKey generatedKey = (SecretKey) session.generateKey(mechanism, secretKeyTemplate);
            return generatedKey;
        } catch (TokenException e) {
            String errorMessage = "";
            throw new HSMCryptoException(errorMessage, e);
        }
    }


    /**
     * When an external key is used for a cryptographic operation, it is necessary get a object handle from HSM for the key.
     * This creates handle for the given {@link SecretKey} inside the HSM.
     *
     * @param secretKey     : The key which requires a handle
     * @return              : {@link SecretKey}
     * @throws HSMCryptoException
     */
    public SecretKey getSecretKeyHandle(SecretKey secretKey) throws HSMCryptoException {

        try {
            return (SecretKey) session.createObject(secretKey);
        } catch (TokenException e) {
            String errorMessage = String.format("Error occurred while generating an object for given secret key.");
            throw new HSMCryptoException(errorMessage, e);
        }
    }
}
