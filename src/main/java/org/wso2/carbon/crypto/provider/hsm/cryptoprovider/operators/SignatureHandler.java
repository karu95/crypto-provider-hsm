package org.wso2.carbon.crypto.provider.hsm.cryptoprovider.operators;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.exception.HSMCryptoException;

/**
 * This class is responsible for handling sign/verify operations.
 */
public class SignatureHandler {

    private static Log log = LogFactory.getLog(SignatureHandler.class);

    private final Session session;

    /**
     * Constructor for signature handler.
     *
     * @param session : Session used to perform sign/verify operation.
     */
    public SignatureHandler(Session session) {
        this.session = session;
    }

    /**
     * Method to digitally sign a given data with the given mechanism.
     *
     * @param dataToSign    : Data to be signed.
     * @param signMechanism : Signing mechanism
     * @param signKey       : Key used for signing.
     * @return signature as a byte array.
     * @throws CryptoException
     */
    public byte[] sign(byte[] dataToSign,
                       PrivateKey signKey, Mechanism signMechanism) throws CryptoException {

        byte[] signature = null;
        if (signMechanism.isFullSignVerifyMechanism() ||
                signMechanism.isSingleOperationSignVerifyMechanism()) {
            try {
                session.signInit(signMechanism, signKey);
                signature = session.sign(dataToSign);
            } catch (TokenException e) {
                String errorMessage = String.format("Error occurred during generating signature using algorithm '%s'" +
                        ".", signMechanism.getName());
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new HSMCryptoException(errorMessage, e);
            }
        } else {
            String errorMessage = String.format("Requested '%s' algorithm for data signing is not a valid " +
                    "signing mechanism.", signMechanism.getName());
            throw new CryptoException(errorMessage);
        }
        return signature;
    }

    /**
     * Method to verify a given data with given mechanism.
     *
     * @param dataToVerify    : Data to be verified.
     * @param signature       : Signature of the data.
     * @param verifyMechanism : verifying mechanism.
     * @param verificationKey : Key used for verification.
     * @return True if verified.
     */
    public boolean verify(byte[] dataToVerify, byte[] signature,
                          PublicKey verificationKey, Mechanism verifyMechanism) throws CryptoException {

        boolean verified = false;
        if (verifyMechanism.isFullSignVerifyMechanism()) {
            try {
                session.verifyInit(verifyMechanism, verificationKey);
                session.verify(dataToVerify, signature);
                verified = true;
            } catch (TokenException e) {
                if (!e.getMessage().equals("")) {
                    String errorMessage = String.format("Error occurred during verifying the signature using " +
                            "algorithm '%s'", verifyMechanism.getName());
                    if (log.isDebugEnabled()) {
                        log.debug(errorMessage, e);
                    }
                    throw new HSMCryptoException(errorMessage, e);
                }
            }
        } else {
            String errorMessage = String.format("Requested '%s' algorithm for signature verification is not a " +
                    "valid sign verification mechanism.", verifyMechanism.getName());
            throw new CryptoException(errorMessage);
        }
        return verified;
    }
}
