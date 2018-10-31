package org.wso2.carbon.crypto.provider.hsm.cryptoprovider.objecthandlers;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Certificate;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.exception.HSMCryptoException;

/**
 * This class is responsible to handle certificate related operations with HSM.
 */
public class CertificateHandler {

    private static Log log = LogFactory.getLog(CertificateHandler.class);

    private final Session session;

    /**
     * Constructor of CertificateHandler instance.
     *
     * @param session : Session associated to handle the certificate related operation.
     */
    public CertificateHandler(Session session) {
        this.session = session;
    }

    /**
     * Method to retrieve a given certificate from the HSM.
     *
     * @param certificateTemplate : Template of the certificate to be retrieved
     * @return retrievedCertificate
     */
    public Object getCertificate(Certificate certificateTemplate) throws CryptoException {

        Object certificate = null;
        try {
            session.findObjectsInit(certificateTemplate);
            Object[] secretKeyArray = session.findObjects(1);
            if (secretKeyArray.length > 0) {
                certificate = secretKeyArray[0];
            }
        } catch (TokenException e) {
            String errorMessage = String.format("Error occurred during retrieving certificate with alias '%s'",
                    String.valueOf(certificateTemplate.getLabel().getCharArrayValue()));
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new HSMCryptoException(errorMessage, e);
        }
        return certificate;
    }
}
