/************************************************************************
 *                                                                       *
 *  Signservice Transaction Signing                                      *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.transactionsigning.common;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.*;

/**
 * Custom implementation of KeyStoreCertificateSource that can be
 * created using an existing java.security.KeyStore.
 */
public class KeyStoreCertificateSource extends CommonCertificateSource {
    private static final Logger log = LoggerFactory.getLogger(KeyStoreCertificateSource.class);

    private KeyStore keyStore;
    private KeyStore.PasswordProtection passwordProtection;

    /**
     * Create instance from an existing keystore.
     *
     * @param keyStore Keystore to use as certificate source.
     */
    public KeyStoreCertificateSource(KeyStore keyStore){
        this.keyStore = keyStore;
    }

    /**
     * Create instance from keystore on local file system.
     *
     * @param keyStorePath the keystore filepath
     * @param keyStorePassword the keystore password
     * @param keyStoreType     the keystore type
     * @throws IOException if the file not exists
     */
    public KeyStoreCertificateSource(String keyStorePath, String keyStorePassword, String keyStoreType) throws IOException {
        this(new File(keyStorePath), keyStoreType, keyStorePassword);
    }

    /**
     * Create instance from keystore file.
     *
     * @param keyStoreFile the keystore file
     * @param keyStorePassword the keystore password
     * @param keyStoreType the keystore type
     * @throws IOException if the file not exists
     */
    public KeyStoreCertificateSource(File keyStoreFile, String keyStorePassword, String keyStoreType) throws IOException {
        this(new FileInputStream(keyStoreFile), keyStoreType, keyStorePassword);
    }

    /**
     * Create instance from input stream.
     *
     * @param keyStoreStream the inputstream with the keystore (can be null to create a new keystore)
     * @param keyStorePassword the keystore password
     * @param keyStoreType the keystore type
     */
    public KeyStoreCertificateSource(InputStream keyStoreStream, String keyStorePassword, String keyStoreType) {
        initKeystore(keyStoreStream, keyStoreType, keyStorePassword);
    }

    private void initKeystore(InputStream keyStoreStream, String keyStorePassword, String keyStoreType) {
        try (InputStream is = keyStoreStream) {
            keyStore = KeyStore.getInstance(keyStoreType);
            final char[] password = (keyStorePassword == null) ? null : keyStorePassword.toCharArray();
            keyStore.load(is, password);
            passwordProtection = new KeyStore.PasswordProtection(password);
        } catch (GeneralSecurityException | IOException e) {
            throw new DSSException("Unable to initialize the keystore", e);
        }
    }

    /**
     * This method allows to retrieve a certificate by its alias
     *
     * @param alias the certificate alias in the keystore
     * @return the certificate
     */
    public CertificateToken getCertificate(String alias) {
        try {
            String aliasToSearch = getKey(alias);
            if (keyStore.containsAlias(aliasToSearch)) {
                Certificate certificate = keyStore.getCertificate(aliasToSearch);
                return DSSUtils.loadCertificate(certificate.getEncoded());
            } else {
                log.warn("Certificate '" + aliasToSearch + "' not found in the keystore");
                return null;
            }
        } catch (GeneralSecurityException e) {
            throw new DSSException("Unable to retrieve certificate from the keystore", e);
        }
    }

    /**
     * This method returns all certificates from the keystore
     */
    @Override
    public List<CertificateToken> getCertificates() {
        List<CertificateToken> list = new ArrayList<>();
        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                Certificate certificate = keyStore.getCertificate(getKey(aliases.nextElement()));
                list.add(DSSUtils.loadCertificate(certificate.getEncoded()));
            }
        } catch (GeneralSecurityException e) {
            throw new DSSException("Unable to retrieve certificates from the keystore", e);
        }
        return Collections.unmodifiableList(list);
    }

    /**
     * This method allows to add a list of certificates to the keystore
     *
     * @param certificates the list of certificates
     */
    public void addAllCertificatesToKeyStore(List<CertificateToken> certificates) {
        for (CertificateToken certificateToken : certificates) {
            addCertificateToKeyStore(certificateToken);
        }
    }

    /**
     * This method allows to add a certificate in the keystore. The generated alias will be the DSS ID.
     *
     * @param certificateToken
     *            the certificate to be added in the keystore
     */
    public void addCertificateToKeyStore(CertificateToken certificateToken) {
        try {
            keyStore.setCertificateEntry(getKey(certificateToken.getDSSIdAsString()), certificateToken.getCertificate());
        } catch (Exception e) {
            throw new DSSException("Unable to add certificate to the keystore", e);
        }
    }

    /**
     * This method allows to remove a certificate from the keystore
     *
     * @param alias
     *            the certificate alias
     */
    public void deleteCertificateFromKeyStore(String alias) throws KeyStoreException {
        try {
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias);
                log.info("Certificate '" + alias + "' successfuly removed from the keystore");
            } else {
                log.warn("Certificate '" + alias + "' not found in the keystore");
            }
        } catch (GeneralSecurityException e) {
            throw new DSSException("Unable to delete certificate from the keystore", e);
        }
    }

    /**
     * This method allows to remove all certificates from the keystore
     */
    public void clearAllCertificates() throws KeyStoreException {
        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                deleteCertificateFromKeyStore(alias);
            }
        } catch (GeneralSecurityException e) {
            throw new DSSException("Unable to clear certificates from the keystore", e);
        }
    }

    /**
     * This method allows to store the keystore in the OutputStream
     *
     * @param os
     *            the OutpuStream where to store the keystore
     */
    public void store(OutputStream os) {
        try {
            keyStore.store(os, passwordProtection.getPassword());
        } catch (GeneralSecurityException | IOException e) {
            throw new DSSException("Unable to store the keystore", e);
        }
    }

    private String getKey(String inputKey) {
        if ("PKCS12".equals(keyStore.getType())) {
            // workaround for https://bugs.openjdk.java.net/browse/JDK-8079616:
            return inputKey.toLowerCase(Locale.ROOT);
        }
        return inputKey;
    }

}
