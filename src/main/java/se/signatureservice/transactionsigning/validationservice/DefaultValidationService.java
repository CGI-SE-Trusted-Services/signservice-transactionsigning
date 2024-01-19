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
package se.signatureservice.transactionsigning.validationservice;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.tsl.TrustProperties;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.apache.commons.lang3.StringUtils;
import se.signatureservice.transactionsigning.ValidatorConfig;
import se.signatureservice.transactionsigning.common.*;
import se.signatureservice.transactionsigning.util.DSSUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DefaultValidationService implements ValidationService {
    private static final Logger log = LoggerFactory.getLogger(DefaultValidationService.class);

    private ValidatorConfig config;
    private boolean initialized;

    private CertificateVerifier certificateVerifier;

    /**
     * Initialize the validation service instance.
     *
     * @param config Configuration to use for the validation service instance.
     * @throws InvalidConfigurationException If an error occurred when initializing due to invalid configuration
     */
    public void init(ValidatorConfig config) throws InvalidConfigurationException {
        this.config = config;

        if(config.getTrustStore() == null){
            throw new InvalidConfigurationException("Validation truststore is missing");
        }

        initialized = true;
    }


    /**
     * Validate signed documents.
     *
     * @param documents List of documents to validate
     * @throws ValidationException If any of the documents contains an invalid signature.
     * @throws ValidationIOException If an intermittent I/O error occurred when validating the signature.
     * @throws InvalidParameterException If an error occurred due an invalid input parameters.
     */
    public void validateDocuments(List<SignedDocument> documents) throws ValidationException, ValidationIOException, InvalidParameterException {
        if(!initialized){
            throw new ValidationException("ValidationService must be initialized before calling validateDocuments");
        }

        try {
            String policyResource = config.getPolicyName();
            for (SignedDocument document : documents) {
                DSSDocument dssDocument = DSSUtils.createDSSDocument(document);
                SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
                validator.setCertificateVerifier(getCertificateVerifier());
                Reports result = validator.validateDocument(policyResource);

                if(log.isDebugEnabled()){
                    log.debug(result.getXmlValidationReport());
                    log.debug(result.getXmlSimpleReport());
                }

                for (String signatureId : result.getSimpleReport().getSignatureIdList()) {
                    Indication indication = result.getSimpleReport().getIndication(signatureId);
                    SubIndication subIndicaton = result.getSimpleReport().getSubIndication(signatureId);
                    if (indication != Indication.TOTAL_PASSED) {
                        throw new ValidationException("Validation failed for signature id (" +
                                signatureId + "). Indication: " + indication + ", Sub indication: " +
                                subIndicaton + " (" + StringUtils.join(result.getSimpleReport().getAdESValidationErrors(signatureId)) + ")");
                    }

                    if (config.isStrictValidation()) {
                        List<Message> warnings = result.getSimpleReport().getAdESValidationWarnings(signatureId);
                        if (warnings != null && warnings.size() > 0) {
                            List<String> warningStrings = new ArrayList<>();
                            for(Message warningMessage : warnings){
                                warningStrings.add(warningMessage.getValue());
                            }
                            throw new ValidationException("Strict validation failed for signature id (" + signatureId + "): " + StringUtils.join(warningStrings, ","));
                        }
                    }
                }
            }
        } catch(Exception e){
            if(e instanceof ValidationException){
                throw e;
            }
            throw new ValidationException("Internal error when performing validation: " + e.getMessage(), e);
        }
    }

    private CertificateVerifier getCertificateVerifier() throws ValidationException {
        if(certificateVerifier == null){
            try {
                certificateVerifier = new CommonCertificateVerifier();

                if(!config.isDisableRevocation()) {
                    certificateVerifier.setCrlSource(new OnlineCRLSource());
                    certificateVerifier.setOcspSource(new OnlineOCSPSource());
                }

                KeyStoreCertificateSource trustedCertificateSource = new KeyStoreCertificateSource(config.getTrustStore());
                TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();
                Map<CertificateToken, List<TrustProperties>> trustPropertiesByCerts = new HashMap<>();
                for(CertificateToken token : trustedCertificateSource.getCertificates()){
                    trustPropertiesByCerts.put(token, new ArrayList<>());
                }
                trustedListsCertificateSource.setTrustPropertiesByCertificates(trustPropertiesByCerts);
                certificateVerifier.setTrustedCertSources(trustedListsCertificateSource);
            } catch(Exception e){
                throw new ValidationException("Failed to initialize certificate verifier: " + e.getMessage(), e);
            }
        }

        return certificateVerifier;
    }

}
