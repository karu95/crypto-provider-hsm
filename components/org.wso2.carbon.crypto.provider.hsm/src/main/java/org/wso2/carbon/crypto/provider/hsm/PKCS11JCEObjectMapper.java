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

import iaik.pkcs.pkcs11.objects.Certificate;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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

/**
 * This class maps PKCS 11 certificates and private keys to JCE certificates and private keys and vice versa.
 */
public class PKCS11JCEObjectMapper {

    private static Log log = LogFactory.getLog(PKCS11JCEObjectMapper.class);

    /**
     * This static method maps JCE certificate to PKCS 11 certificate.
     *
     * @param certificate : JCE Certificate
     * @return PKCS11 Certificate data {@link PKCS11CertificateData}.
     * @throws CryptoException
     */
    public static PKCS11CertificateData mapCertificateJCEToPKCS11(java.security.cert.Certificate certificate)
            throws CryptoException {

        if (!(certificate instanceof X509Certificate)) {
            String errorMessage = "This doesn't support for conversion of certificates in the provided format.";
            log.error(errorMessage);
            throw new CryptoException(errorMessage);
        }

        X509Certificate x509Certificate = (X509Certificate) certificate;
        X509PublicKeyCertificate cert = new X509PublicKeyCertificate();
        cert.getSubject().setByteArrayValue(x509Certificate.getSubjectX500Principal().getEncoded());
        cert.getIssuer().setByteArrayValue(x509Certificate.getIssuerX500Principal().getEncoded());
        cert.getSerialNumber().setByteArrayValue(x509Certificate.getSerialNumber().toByteArray());
        try {
            cert.getValue().setByteArrayValue(x509Certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            String errorMessage = "Error occured while encoding the certificate.";
            throw new CryptoException(errorMessage, e);
        }

        PublicKey publicKey = certificate.getPublicKey();
        if (!(publicKey instanceof java.security.interfaces.RSAPublicKey)) {
            String errorMessage = "Implementation supports only for RSA public key conversions.";
            log.error(errorMessage);
            throw new CryptoException(errorMessage);
        }
        java.security.interfaces.RSAPublicKey rsaPublicKeySpec = (java.security.interfaces.RSAPublicKey) publicKey;
        RSAPublicKey rsaPublicKey = new RSAPublicKey();
        rsaPublicKey.getSubject().setByteArrayValue(x509Certificate.getSubjectX500Principal().getEncoded());
        rsaPublicKey.getModulus().setByteArrayValue(rsaPublicKeySpec.getModulus().toByteArray());
        rsaPublicKey.getPublicExponent().setByteArrayValue(rsaPublicKeySpec.getPublicExponent().toByteArray());
        return new PKCS11CertificateData(cert, rsaPublicKey);
    }

    /**
     * This static method maps PKCS 11 certificate to JCE certificate.
     *
     * @param certificate : PKCS11 certificate.
     * @return JCE certificate {@link java.security.cert.Certificate}.
     * @throws CryptoException
     */
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

    /**
     * This static method maps JCE private key to PKCS 11 private key.
     *
     * @param privateKey : JCE private key.
     * @return PKCS 11 private key {@link PrivateKey}.
     * @throws CryptoException
     */
    public static PrivateKey mapPrivateKeyJCEToPKCS11(java.security.PrivateKey privateKey) throws CryptoException {

        if (!(privateKey instanceof java.security.interfaces.RSAPrivateKey)) {
            String errorMessage = "Implementation supports only for RSA private key conversions.";
            log.error(errorMessage);
            throw new CryptoException(errorMessage);
        }

        java.security.interfaces.RSAPrivateKey rsaPrivateKeySpec = (java.security.interfaces.RSAPrivateKey) privateKey;
        RSAPrivateKey rsaPrivateKey = new RSAPrivateKey();
        rsaPrivateKey.getModulus().setByteArrayValue(rsaPrivateKeySpec.getModulus().toByteArray());
        rsaPrivateKey.getPrivateExponent().setByteArrayValue(rsaPrivateKeySpec.getPrivateExponent().toByteArray());
        return rsaPrivateKey;
    }

    /**
     * This static method maps PKCS 11 private key to JCE private key.
     *
     * @param privateKey : PKCS 11 Private key.
     * @return JCE private key {@link java.security.PrivateKey}.
     * @throws CryptoException
     */
    public static java.security.PrivateKey mapPrivateKeyPKCS11ToJCE(PrivateKey privateKey) throws CryptoException {

        if (!(privateKey instanceof RSAPrivateKey)) {
            String errorMessage = String.format("Retrieved private key %s is not a RSA Private Key.",
                    new String(privateKey.getLabel().getCharArrayValue()));
            log.error(errorMessage);
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
