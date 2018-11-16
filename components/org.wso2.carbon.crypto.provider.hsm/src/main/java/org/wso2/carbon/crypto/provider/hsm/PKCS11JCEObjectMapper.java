package org.wso2.carbon.crypto.provider.hsm;

import iaik.pkcs.pkcs11.objects.Certificate;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import org.wso2.carbon.crypto.api.CryptoException;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;

public class PKCS11JCEObjectMapper {

    public static PKCS11CertificateData mapCertificateJCEToPKCS11(java.security.cert.Certificate certificate)
            throws CryptoException {

        if (!(certificate instanceof X509Certificate)) {
            throw new CryptoException();
        }

        X509Certificate x509Certificate = (X509Certificate) certificate;
        X509PublicKeyCertificate cert = new X509PublicKeyCertificate();
        cert.getSubject().setByteArrayValue(x509Certificate.getSubjectX500Principal().getEncoded());
        cert.getIssuer().setByteArrayValue(x509Certificate.getIssuerX500Principal().getEncoded());
        cert.getSerialNumber().setByteArrayValue(x509Certificate.getSerialNumber().toByteArray());
        try {
            cert.getValue().setByteArrayValue(x509Certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new CryptoException();
        }

        PublicKey publicKey = certificate.getPublicKey();
        if (!(publicKey instanceof java.security.interfaces.RSAPublicKey)) {
            throw new CryptoException();
        }
        java.security.interfaces.RSAPublicKey rsaPublicKeySpec = (java.security.interfaces.RSAPublicKey) publicKey;
        RSAPublicKey rsaPublicKey = new RSAPublicKey();
        rsaPublicKey.getModulus().setByteArrayValue(rsaPublicKeySpec.getModulus().toByteArray());
        rsaPublicKey.getPublicExponent().setByteArrayValue(rsaPublicKeySpec.getPublicExponent().toByteArray());

        return new PKCS11CertificateData(cert, rsaPublicKey);
    }

    public static java.security.cert.Certificate mapCertificatePKCS11ToJCE(Certificate certificate)
            throws CryptoException {

        if (!(certificate instanceof X509PublicKeyCertificate)) {
            String errorMessage = String.format("Retrieved %s certificate format is not supported by the HSM " +
                    "based crypto provider.", new String(certificate.getLabel().getCharArrayValue()));
            throw new CryptoException(errorMessage);
        }

        byte[] x509Certificate = ((X509PublicKeyCertificate) certificate).getValue().getByteArrayValue();
        try {
            return CertificateFactory.getInstance("X.509").generateCertificate(
                    new ByteArrayInputStream(x509Certificate));
        } catch (CertificateException e) {
            String errorMessage = String.format("Error occurred while generating X.509 certificate from the " +
                    "retrieved certificate from the HSM.");
            throw new CryptoException(errorMessage, e);
        }
    }

    public static PrivateKey mapPrivateKeyJCEToPKCS11(java.security.PrivateKey privateKey) throws CryptoException {

        if (!(privateKey instanceof java.security.interfaces.RSAPrivateKey)) {
            throw new CryptoException();
        }

        java.security.interfaces.RSAPrivateKey rsaPrivateKeySpec = (java.security.interfaces.RSAPrivateKey) privateKey;
        RSAPrivateKey rsaPrivateKey = new RSAPrivateKey();
        rsaPrivateKey.getModulus().setByteArrayValue(rsaPrivateKeySpec.getModulus().toByteArray());
        rsaPrivateKey.getPrivateExponent().setByteArrayValue(rsaPrivateKeySpec.getPrivateExponent().toByteArray());
        return rsaPrivateKey;
    }

    public static java.security.PrivateKey mapPrivateKeyPKCS11ToJCE(PrivateKey privateKey) throws CryptoException {

        if (!(privateKey instanceof RSAPrivateKey)) {
            String errorMessage = String.format("Retrieved private key %s is not a RSA Private Key.",
                    new String(privateKey.getLabel().getCharArrayValue()));
            throw new CryptoException(errorMessage);
        }

        RSAPrivateKey retrievedRSAKey = (RSAPrivateKey) privateKey;
        BigInteger privateExponent = new BigInteger(retrievedRSAKey.
                getPrivateExponent().getByteArrayValue());
        BigInteger modulus = new BigInteger(retrievedRSAKey.getModulus().getByteArrayValue());
        String keyGenerationAlgorithm = "RSA";
        try {
            return KeyFactory.getInstance(keyGenerationAlgorithm).generatePrivate(new
                    RSAPrivateKeySpec(modulus, privateExponent));
        } catch (InvalidKeySpecException e) {
            String errorMessage = String.format("Provided key specification is invalid for key alias '%s'",
                    new String(privateKey.getLabel().getCharArrayValue()));
            throw new CryptoException(errorMessage, e);
        } catch (NoSuchAlgorithmException e) {
            String errorMessage = String.format("Invalid key generation algorithm '%s'.", keyGenerationAlgorithm);
            throw new CryptoException(errorMessage, e);
        }
    }
}
