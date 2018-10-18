package org.wso2.carbon.crypto.provider.hsm.cryptoprovider.objecthandlers;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Key;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.exception.HSMCryptoException;

/**
 * This class is responsible to retrieve keys from the HSM.
 */
public class KeyHandler {

    private static Log log = LogFactory.getLog(KeyHandler.class);

    private final Session session;

    /**
     * Constructor of key handler instance.
     *
     * @param session
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
    public Object retrieveKey(Key keyTemplate) throws CryptoException {

        Object key = null;
        try {
            session.findObjectsInit(keyTemplate);
            Object[] secretKeyArray = session.findObjects(1);
            if (secretKeyArray.length > 0) {
                key = secretKeyArray[0];
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

    public Key generateKey(Key keyTemplate, Mechanism mechanism) throws HSMCryptoException {
        try {
            Key generatedKey = (Key) session.generateKey(mechanism, keyTemplate);
            return generatedKey;
        } catch (TokenException e) {
            throw new HSMCryptoException();
        }
    }
}
