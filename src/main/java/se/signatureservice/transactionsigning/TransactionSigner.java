/************************************************************************
 *                                                                       *
 *  Signature Service - Transaction Signing Library                      *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3 of the License, or any later version.                      *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.transactionsigning;

import se.signatureservice.transactionsigning.common.*;
import se.signatureservice.transactionsigning.signservice.SignService;
import se.signatureservice.transactionsigning.supportservice.SupportService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;

/**
 * Transaction signer class to sign transactions, consisting of one or
 * more documents. Documents are signed according to the ETSI specifications
 * for advanced signatures (XAdES, PAdES and CAdES).
 *
 * @author Tobias Agerberg
 */
final public class TransactionSigner {
    private final static Logger log = LoggerFactory.getLogger(TransactionSigner.class);
    private SupportService supportService;
    private SignService signService;
    private SignerConfig config;

    private TransactionSigner(SignerConfig config) throws InvalidConfigurationException {
        this.config = config;

        supportService = ServiceManager.getSupportService();
        supportService.init(config);

        signService = ServiceManager.getSignService();
        signService.init(config);
    }

    /**
     * Sign a single document
     *
     * @param document Document to sign
     * @return Signed document
     * @throws SignatureException If an internal error occurred during signature request.
     * @throws SignatureIOException If an intermittent I/O error occurred during signature request.
     * @throws InvalidParameterException If an error occurred due to an invalid signature request.
     */
    public SignedDocument signDocument(Document document) throws SignatureException, SignatureIOException, InvalidParameterException {
        List<Document> documents = new ArrayList<>();
        documents.add(document);
        List<SignedDocument> signedDocuments = signDocuments(documents);
        if(signedDocuments != null && signedDocuments.size() == 1){
            return signedDocuments.get(0);
        }
        return null;
    }

    /**
     * Sign a list of documents
     *
     * @param documents List of documents to sign
     * @return List of signed documents
     * @throws SignatureException If an internal error occurred during signature request.
     * @throws SignatureIOException If an intermittent I/O error occurred during signature request.
     * @throws InvalidParameterException If an error occurred due to an invalid signature request.
     */
    public List<SignedDocument> signDocuments(List<Document> documents) throws SignatureException, SignatureIOException, InvalidParameterException {
        try {
            String request = supportService.generateSignRequest(documents);
            log.info("Generated request: " + request);

            String response = signService.requestSignature(request);
            log.info("Got signature response: " + response);

            return supportService.processSignResponse(response);
        } catch(Exception e){
            if(e instanceof SignatureException || e instanceof SignatureIOException || e instanceof InvalidParameterException){
                throw e;
            }
            throw new SignatureException("Failed to sign document(s): " + e.getMessage(), e);
        }
    }

    /**
     * Builder class to use when building a TransactionSigner instance.
     */
    public static class Builder {
        SignerConfig config;

        /**
         * Create new TransactionSigner builder
         */
        public Builder(){
            config = new SignerConfig();
            config.setSslAlgorithm(SignerConfig.DEFAULT_SIGN_SSL_ALGORITHM);
            config.setSignatureAlgorithm(SignerConfig.DEFAULT_SIGNATUREALGORITHM);
            config.setCadesSignatureLevel(SignerConfig.DEFAULT_CADES_SIGNATURELEVEL);
            config.setCadesSignaturePacking(SignerConfig.DEFAULT_CADES_SIGNATUREPACKING);
            config.setPadesSignatureLevel(SignerConfig.DEFAULT_PADES_SIGNATURELEVEL);
            config.setPadesSignaturePacking(SignerConfig.DEFAULT_PADES_SIGNATUREPACKING);
            config.setXadesSignatureLevel(SignerConfig.DEFAULT_XADES_SIGNATURELEVEL);
            config.setXadesSignaturePacking(SignerConfig.DEFAULT_XADES_SIGNATUREPACKAGING);
            config.setXadesSignedInfoCanonicalizationMethod(SignerConfig.DEFAULT_XADES_SIGNEDINFOCANONICALIZATIONMETHOD);
            config.setXadesSignedPropertiesCanonicalizationMethod(SignerConfig.DEFAULT_XADES_SIGNEDPROPERTIESCANONICALIZATIONMETHOD);
            config.setXadesXPathLocation(SignerConfig.DEFAULT_XADES_XPATHLOCATIONSTRING);
        }

        /**
         * Specify signature type. This depends on the configuration of the remote
         * signature service and must match a valid pre-configured signature type.
         *
         * @param signType Signature type configuration to use
         * @return Updated builder
         */
        public Builder signType(String signType){
            config.setSignType(signType);
            return this;
        }

        /**
         * Specify key ID. This depends on the configuration of the remote
         * signature service and must match a valid pre-configured key ID.
         *
         * @param keyId Key ID configuration to use
         * @return Updated builder
         */
        public Builder keyId(String keyId){
            config.setKeyId(keyId);
            return this;
        }

        /**
         * Specify URL to API endpoint to use when requesting signatures.
         *
         * @param apiEndpoint URL to API endpoint
         * @return Updated builder
         */
        public Builder apiEndpoint(String apiEndpoint){
            config.setApiEndpoint(apiEndpoint);
            return this;
        }

        /**
         * Specify an API KEY to use for authentication to the API endpoint.
         * If this is required or not depends on the configuration of the
         * remote signing service.
         *
         * @param apiKey API Key to use for authentication
         * @return Updated builder
         */
        public Builder apiKey(String apiKey){
            config.setApiKey(apiKey);
            return this;
        }

        /**
         * Specify a keystore containing client certificate and private key
         * to use when authenticating to the API endpoint. If this is required
         * or not depends on the configuration of the remote signing service.
         *
         * @param keyStorePath Path to keystore. This could point to either a
         *                     path on the classpath or on the file system, with
         *                     classpath having higher priority.
         * @return Updated builder
         */
        public Builder sslKeyStore(String keyStorePath, String keyStorePassword, String keyStoreType){
            try {
                KeyStore keyStore = KeyStore.getInstance(keyStoreType);
                keyStore.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());
                config.setSslKeyStore(keyStore);
                config.setSslKeyStorePassword(keyStorePassword);
            } catch(Exception e){
                log.error("Failed to load keystore from " + keyStorePath + ": " + e.getMessage());
            }
            return this;
        }

        /**
         * Specify a keystore containing client certificate and private key
         * to use when authenticating to the API endpoint. If this is required
         * or not depends on the configuration of the remote signing service.
         *
         * @param keyStore Keystore to use.
         * @return Updated builder
         */
        public Builder sslKeyStore(KeyStore keyStore, String keyStorePassword){
            config.setSslKeyStore(keyStore);
            config.setSslKeyStorePassword(keyStorePassword);
            return this;
        }

        /**
         * Specify a SSL truststore to use when validating the API endpoint
         * SSL server certificate. If not specified the default Java JRE
         * trust store will be used.
         *
         * @param trustStorePath Path to trust store. This could point to either
         *                       a path on the classpath or on the file system,
         *                       with classpath having higher priority.
         * @return Updated builder
         */
        public Builder sslTrustStore(String trustStorePath, String trustStorePassword, String trustStoreType){
            try {
                KeyStore trustStore = KeyStore.getInstance(trustStoreType);
                trustStore.load(new FileInputStream(trustStorePath), trustStorePassword.toCharArray());
                config.setSslTrustStore(trustStore);
            } catch(Exception e){
                log.error("Failed to load truststore from " + trustStorePath + ": " + e.getMessage());
            }
            return this;
        }

        /**
         * Specify a SSL truststore to use when validating the API endpoint
         * SSL server certificate. If not specified the default Java JRE
         * trust store will be used.
         *
         * @param trustStore Truststore to use.
         * @return Updated builder
         */
        public Builder sslTrustStore(KeyStore trustStore){
            config.setSslTrustStore(trustStore);
            return this;
        }

        /**
         * Specify SSL/TLS algorithm to use when connecting to the API endpoint if the
         * connection is using HTTPS protocol. If not specified the default value
         * will be used ("TLSv1.2")
         *
         * @param sslAlgorithm SSL/TLS Algorithm to use
         * @return Updated builder
         */
        public Builder sslAlgorithm(String sslAlgorithm){
            config.setSslAlgorithm(sslAlgorithm);
            return this;
        }

        /**
         * Se signature algorithm to use when signing documents.
         *
         * @param signatureAlgorithm Signature algorithm to use
         * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Signature">Signature Algorithms</a>
         * @return Updated builder
         */
        public Builder signatureAlgorithm(String signatureAlgorithm){
            config.setSignatureAlgorithm(signatureAlgorithm);
            return this;
        }

        /**
         * Set signature level to use when signing binary documents using CAdES.
         * Default signature level is "CAdES-BASELINE-B"
         *
         * @param cadESSignatureLevel Signature level to use for CAdES
         * @return Updated builder
         */
        public Builder cadESSignatureLevel(String cadESSignatureLevel){
            config.setCadesSignatureLevel(cadESSignatureLevel);
            return this;
        }

        /**
         * Set signature packing to use when signing binary documents using CAdES.
         * Default signature packing is "ENVELOPING"
         *
         * @param cadESSignaturePacking Signature packing to use for CAdES
         * @return Updated builder
         */
        public Builder cadESSignaturePacking(String cadESSignaturePacking){
            config.setCadesSignaturePacking(cadESSignaturePacking);
            return this;
        }

        /**
         * Set signature level to use when signing PDF documents using PAdES.
         * Default signature level is "PAdES-BASELINE-B"
         *
         * @param padESSignatureLevel Signature level to use for PAdES
         * @return Updated builder
         */
        public Builder padESSignatureLevel(String padESSignatureLevel){
            config.setPadesSignatureLevel(padESSignatureLevel);
            return this;
        }

        /**
         * Set signature packing to use when signing PDF documents using PAdES.
         * Default signature packing is "ENVELOPED"
         *
         * @param padESSignaturePacking Signature packing to use for PAdES
         * @return Updated builder
         */
        public Builder padESSignaturePacking(String padESSignaturePacking){
            config.setPadesSignaturePacking(padESSignaturePacking);
            return this;
        }

        /**
         * Set signature level to use when signing XML documents using XAdES.
         * Default signature level is "XAdES-BASELINE-B"
         *
         * @param xadESSignatureLevel Signature level to use for XAdES
         * @return Updated builder
         */
        public Builder xadESSignatureLevel(String xadESSignatureLevel){
            config.setXadesSignatureLevel(xadESSignatureLevel);
            return this;
        }

        /**
         * Set signature packing to use when signing XML documents using XAdES.
         * Default signature packing is "ENVELOPED"
         *
         * @param xadESSignaturePacking Signature packing to use for XAdES
         * @return Updated builder
         */
        public Builder xadESSignaturePacking(String xadESSignaturePacking){
            config.setXadesSignaturePacking(xadESSignaturePacking);
            return this;
        }

        /**
         * Specify canonicalization method to use when performing canonicalization of SignedInfo
         * XML element. Default method is "http://www.w3.org/2001/10/xml-exc-c14n#"
         *
         * @param method Canonicalization method to use for XAdES regarding SignedInfo
         * @return Updated builder
         */
        public Builder xadESSignedInfoCanonicalizationMethod(String method){
            config.setXadesSignedInfoCanonicalizationMethod(method);
            return this;
        }

        /**
         * Specify canonicalization method to use when performing canonicalization of SignedProperties
         * XML element. Default method is "http://www.w3.org/2001/10/xml-exc-c14n#"
         *
         * @param method Canonicalization method to use for XAdES regarding SignedProperties
         * @return Updated builder
         */
        public Builder xadESSignedPropertiesCanonicalizationMethod(String method){
            config.setXadesSignedPropertiesCanonicalizationMethod(method);
            return this;
        }

        /**
         * Specify XPath expression to use that defines the area where the signature
         * will be added when signing XML documents using XAdES. Default XPath location
         * is "node()[not(self::Signature)]"
         * @param xPathLocationString XPath expression to use
         * @return Updated builder
         */
        public Builder xadESXPathLocationString(String xPathLocationString){
            config.setXadesXPathLocation(xPathLocationString);
            return this;
        }

        /**
         * Build the transaction signer.
         *
         * @return TransactionSigner instance based on builder settings.
         * @throws InvalidConfigurationException If an error occurred when building transaction signer
         */
        public TransactionSigner build() throws InvalidConfigurationException {
            return new TransactionSigner(config);
        }
    }
}
