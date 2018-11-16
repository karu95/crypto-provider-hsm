package org.wso2.carbon.crypto.provider.hsm;

import iaik.pkcs.pkcs11.objects.Certificate;
import iaik.pkcs.pkcs11.objects.PublicKey;

public class PKCS11CertificateData {

    private Certificate certificate;
    private PublicKey publicKey;

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
