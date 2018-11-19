package org.wso2.carbon.crypto.provider.hsm;

import iaik.pkcs.pkcs11.objects.Certificate;
import iaik.pkcs.pkcs11.objects.PublicKey;

/**
 * Instance of this class holds {@link Certificate} and {@link PublicKey} of the PKCS11 certificates.
 */
public class PKCS11CertificateData {

    private Certificate certificate;
    private PublicKey publicKey;

    /**
     * Constructor of {@link PKCS11CertificateData}.
     *
     * @param certificate :Public key certificate.
     * @param publicKey   :Public key.
     */
    public PKCS11CertificateData(Certificate certificate, PublicKey publicKey) {

        this.certificate = certificate;
        this.publicKey = publicKey;
    }

    public Certificate getCertificate() {

        return certificate;
    }

    public PublicKey getPublicKey() {

        return publicKey;
    }
}
