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
package se.signatureservice.transactionsigning;

import java.security.KeyStore;

/**
 * Class containing transaction signer configuration.
 *
 * @author Tobias Agerberg
 */
public class SignerConfig {
    public final static String DEFAULT_SIGN_SSL_ALGORITHM = "TLSv1.2";
    public final static String DEFAULT_SIGNATUREALGORITHM = "SHA256withRSA";
    public final static String DEFAULT_XADES_SIGNATURELEVEL = "XAdES-BASELINE-B";
    public final static String DEFAULT_XADES_SIGNATUREPACKAGING = "ENVELOPED";
    public final static String DEFAULT_XADES_SIGNEDINFOCANONICALIZATIONMETHOD = "http://www.w3.org/2001/10/xml-exc-c14n#";
    public final static String DEFAULT_XADES_SIGNEDPROPERTIESCANONICALIZATIONMETHOD = "http://www.w3.org/2001/10/xml-exc-c14n#";
    public final static String DEFAULT_XADES_XPATHLOCATIONSTRING = "node()[not(self::Signature)]";
    public final static String DEFAULT_PADES_SIGNATURELEVEL = "PAdES-BASELINE-B";
    public final static String DEFAULT_PADES_SIGNATUREPACKING = "ENVELOPED";
    public final static String DEFAULT_CADES_SIGNATURELEVEL = "CAdES-BASELINE-B";
    public final static String DEFAULT_CADES_SIGNATUREPACKING = "ENVELOPING";

    /**
     * API endpoint to use when requesting signature.
     */
    private String apiEndpoint;

    /**
     * Signature type to request.
     */
    private String signType;

    /**
     * Key identifier to request.
     */
    private String keyId;

    /**
     * API key to use in authorization header when requesting
     * signatures. If this is needed depends on the remote signature
     * service configuration.
     */
    private String apiKey;

    /**
     * Keystore containing client certificate and private key to use
     * when requesting signature. If this is needed depends on the
     * remote signature service configuration.
     */
    private KeyStore sslKeyStore;

    /**
     * Password protecting the private key within the sslKeyStore.
     */
    private String sslKeyStorePassword;

    /**
     * Optional SSL truststore to use when sending requests. If not
     * specified the default JRE truststore will be used, containing
     * publicly trusted issuers.
     */
    private KeyStore sslTrustStore;

    /**
     * SSL Algorithm to use. Default algorithm is "TLSv1.2"
     */
    private String sslAlgorithm;

    /**
     * Signature algorithm to use when signing document.
     * Default: "SHA256withRSA"
     */
    private String signatureAlgorithm;

    /**
     * XAdES Signature level to use for XML-documents.
     * Default: "XAdES-BASELINE-B"
     */
    private String xadesSignatureLevel;

    /**
     * XAdES Signature packing to use for XML-documents.
     * Default: "ENVELOPED"
     */
    private String xadesSignaturePacking;

    /**
     * XAdES canonicalization method to use for SignedInfo element.
     * Default: "http://www.w3.org/2001/10/xml-exc-c14n#"
     */
    private String xadesSignedInfoCanonicalizationMethod;

    /**
     * XAdES canonicalization method to use for SignedProperties element.
     * Default: "http://www.w3.org/2001/10/xml-exc-c14n#"
     */
    private String xadesSignedPropertiesCanonicalizationMethod;

    /**
     * XAdES XPath location string to use.
     * Default: "node()[not(self::Signature)]"
     */
    private String xadesXPathLocation;

    /**
     * PAdES Signature level to use for PDF-documents.
     * Default: "PAdES-BASELINE-B"
     */
    private String padesSignatureLevel;

    /**
     * PAdES Signature packing to use for PDF-documents.
     * Default: "ENVELOPED"
     */
    private String padesSignaturePacking;

    /**
     * CAdES Signature level to use for generic documents.
     * Default: "CAdES-BASELINE-B"
     */
    private String cadesSignatureLevel;

    /**
     * CAdES Signature packing to use for generic documents.
     * Default: ENVELOPING
     */
    private String cadesSignaturePacking;

    public String getApiEndpoint() {
        return apiEndpoint;
    }

    public void setApiEndpoint(String apiEndpoint) {
        this.apiEndpoint = apiEndpoint;
    }

    public String getSignType() {
        return signType;
    }

    public void setSignType(String signType) {
        this.signType = signType;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public KeyStore getSslKeyStore() {
        return sslKeyStore;
    }

    public void setSslKeyStore(KeyStore sslKeyStore) {
        this.sslKeyStore = sslKeyStore;
    }

    public String getSslKeyStorePassword() {
        return sslKeyStorePassword;
    }

    public void setSslKeyStorePassword(String sslKeyStorePassword) {
        this.sslKeyStorePassword = sslKeyStorePassword;
    }

    public KeyStore getSslTrustStore() {
        return sslTrustStore;
    }

    public void setSslTrustStore(KeyStore sslTrustStore) {
        this.sslTrustStore = sslTrustStore;
    }

    public String getSslAlgorithm() {
        return sslAlgorithm;
    }

    public void setSslAlgorithm(String sslAlgorithm) {
        this.sslAlgorithm = sslAlgorithm;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public String getXadesSignatureLevel() {
        return xadesSignatureLevel;
    }

    public void setXadesSignatureLevel(String xadesSignatureLevel) {
        this.xadesSignatureLevel = xadesSignatureLevel;
    }

    public String getXadesSignaturePacking() {
        return xadesSignaturePacking;
    }

    public void setXadesSignaturePacking(String xadesSignaturePacking) {
        this.xadesSignaturePacking = xadesSignaturePacking;
    }

    public String getXadesSignedInfoCanonicalizationMethod() {
        return xadesSignedInfoCanonicalizationMethod;
    }

    public void setXadesSignedInfoCanonicalizationMethod(String xadesSignedInfoCanonicalizationMethod) {
        this.xadesSignedInfoCanonicalizationMethod = xadesSignedInfoCanonicalizationMethod;
    }

    public String getXadesSignedPropertiesCanonicalizationMethod() {
        return xadesSignedPropertiesCanonicalizationMethod;
    }

    public void setXadesSignedPropertiesCanonicalizationMethod(String xadesSignedPropertiesCanonicalizationMethod) {
        this.xadesSignedPropertiesCanonicalizationMethod = xadesSignedPropertiesCanonicalizationMethod;
    }

    public String getXadesXPathLocation() {
        return xadesXPathLocation;
    }

    public void setXadesXPathLocation(String xadesXPathLocation) {
        this.xadesXPathLocation = xadesXPathLocation;
    }

    public String getPadesSignatureLevel() {
        return padesSignatureLevel;
    }

    public void setPadesSignatureLevel(String padesSignatureLevel) {
        this.padesSignatureLevel = padesSignatureLevel;
    }

    public String getPadesSignaturePacking() {
        return padesSignaturePacking;
    }

    public void setPadesSignaturePacking(String padesSignaturePacking) {
        this.padesSignaturePacking = padesSignaturePacking;
    }

    public String getCadesSignatureLevel() {
        return cadesSignatureLevel;
    }

    public void setCadesSignatureLevel(String cadesSignatureLevel) {
        this.cadesSignatureLevel = cadesSignatureLevel;
    }

    public String getCadesSignaturePacking() {
        return cadesSignaturePacking;
    }

    public void setCadesSignaturePacking(String cadesSignaturePacking) {
        this.cadesSignaturePacking = cadesSignaturePacking;
    }
}