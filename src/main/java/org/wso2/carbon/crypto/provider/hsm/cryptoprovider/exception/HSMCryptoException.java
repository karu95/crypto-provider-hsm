package org.wso2.carbon.crypto.provider.hsm.cryptoprovider.exception;

import iaik.pkcs.pkcs11.TokenException;
import org.wso2.carbon.crypto.api.CryptoException;

/**
 * Extension of {@link CryptoException}
 * This exception will be thrown if something unexpected happened during a HSM based crypto operation.
 */
public class HSMCryptoException extends CryptoException {

    private String errorCode;

    public HSMCryptoException() {

        super();
    }

    public HSMCryptoException(String message, Throwable e) {

        super(message, e);
        if (e instanceof TokenException) {
            this.errorCode = e.getMessage();
        }
    }

    public String getErrorCode() {

        return this.errorCode;
    }

    protected void setErrorCode(String errorCode) {

        this.errorCode = errorCode;
    }
}
