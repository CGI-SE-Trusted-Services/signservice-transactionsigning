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
import se.signatureservice.transactionsigning.validationservice.ValidationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;

/**
 * Transaction validator class to validate signed transactions, consisting of one or
 * more signed documents. Signed documents should be signed according to the ETSI
 * specifications for advanced signatures (XAdES, PAdES and CAdES).
 *
 * @author Tobias Agerberg
 */
final public class TransactionValidator {
    private final static Logger log = LoggerFactory.getLogger(TransactionSigner.class);

    private ValidationService validationService;
    private ValidatorConfig config;

    private TransactionValidator(ValidatorConfig config) throws InvalidConfigurationException {
        this.config = config;

        validationService = ServiceManager.getValidationService();
        validationService.init(config);
    }

    /**
     * Validate a single signed document
     *
     * @param document Signed document to validate
     * @throws ValidationException If any of the documents contains an invalid signature.
     * @throws ValidationIOException If an intermittent I/O error occurred when validating the signature.
     * @throws InvalidParameterException If an error occurred due an invalid input parameters.
     */
    public void validateDocument(SignedDocument document) throws ValidationException, ValidationIOException, InvalidParameterException {
        List<SignedDocument> documents = new ArrayList<>();
        documents.add(document);
        validateDocuments(documents);
    }

    /**
     * Validate a list of signed documents
     *
     * @param documents List of signed documents
     * @throws ValidationException If any of the documents contains an invalid signature.
     * @throws ValidationIOException If an intermittent I/O error occurred when validating the signature.
     * @throws InvalidParameterException If an error occurred due an invalid input parameters.
     */
    public void validateDocuments(List<SignedDocument> documents) throws ValidationException, ValidationIOException, InvalidParameterException {
        validationService.validateDocuments(documents);
    }

    /**
     * Builder class to use when building a TransactionValidator instance.
     */
    public static class Builder {
        ValidatorConfig config;

        /**
         * Create new TransactionValidator builder
         */
        public Builder() {
            config = new ValidatorConfig();

            config.setPolicyName(ValidatorConfig.DEFAULT_VALIDATION_POLICY_NAME);
            config.setDisableRevocation(ValidatorConfig.DEFAULT_VALIDATION_DISABLE_REVOCATIONCHECK);
            config.setStrictValidation(ValidatorConfig.DEFAULT_VALIDATION_STRICT);
        }

        /**
         * Specify a trust store to use when validating signing certificates that
         * were used to signed the documents to be validated.
         *
         * @param trustStore Truststore to use.
         * @return Updated builder
         */
        public Builder trustStore(KeyStore trustStore){
            config.setTrustStore(trustStore);
            return this;
        }

        /**
         * Specify a trust store to use when validating signing certificates that
         * were used to signed the documents to be validated.
         *
         * @param trustStorePath Path to trust store to use containing trust anchors. This could point to either a path on the
         *                       classpath or on the file system, with classpath having higher priority.
         * @param trustStorePassword Password that protects the trust store.
         * @return Updated builder
         */
        public Builder trustStore(String trustStorePath, String trustStorePassword, String trustStoreType){
            try {
                KeyStore trustStore = KeyStore.getInstance(trustStoreType);
                trustStore.load(new FileInputStream(trustStorePath), trustStorePassword.toCharArray());
                config.setTrustStore(trustStore);
            } catch(Exception e){
                log.error("Failed to load truststore from " + trustStorePath + ": " + e.getMessage());
            }
            return this;
        }

        /**
         * Specify a custom validation policy file to use when validating
         * documents. The policy name must be resource path name that is
         * available in the class path. Default is "/validationpolicy.xml"
         *
         * @param policyName Custom policy name to use
         * @return Updated builder
         */
        public Builder customValidationPolicy(String policyName){
            config.setPolicyName(policyName);
            return this;
        }

        /**
         * Disable revocation checking when validating signature certificates.
         * This will prevent any CRL or OCSP-responses to be fetched.
         *
         * @return Updated builder
         */
        public Builder disableRevocationCheck(){
            config.setDisableRevocation(true);
            return this;
        }

        /**
         * Enable strict validation. During strict validation any warnings in the
         * validation process will cause the validation to fail.
         *
         * @return Updated builder
         */
        public Builder enableStrictValidation(){
            config.setStrictValidation(true);
            return this;
        }

        /**
         * Build the TransactionValidator instance based on builder settings.
         * @return TransactionValidator instance
         * @throws InvalidConfigurationException If an error occurred when building the TransactionValidator.
         */
        public TransactionValidator build() throws InvalidConfigurationException {
            return new TransactionValidator(config);
        }
    }
}
