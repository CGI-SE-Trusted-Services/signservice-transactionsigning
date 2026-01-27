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
package se.signatureservice.transactionsigning

import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier
import se.signatureservice.transactionsigning.validationservice.DefaultValidationService
import spock.lang.Specification

import java.security.KeyStore

class TransactionValidatorSpec extends Specification {
    def "test builder using in-memory validation truststore"(){
        setup:
        KeyStore validationTrustStore = KeyStore.getInstance("JKS")
        new FileInputStream(new File("src/test/resources/validation-truststore.jks")).withCloseable { fis ->
            validationTrustStore.load(fis, "foo123".toCharArray())
        }

        when:
        TransactionValidator validator = new TransactionValidator.Builder()
            .trustStore(validationTrustStore)
            .build()

        then:
        validator != null
        (validator.validationService as DefaultValidationService).config.getTrustStore() != null
        CommonCertificateVerifier certificateVerifier = ((DefaultValidationService)validator.validationService).getCertificateVerifier() as CommonCertificateVerifier
        certificateVerifier != null
        certificateVerifier.getTrustedCertSources().numberOfCertificates == 13
    }

    def "test builder using file-based validation truststore"(){
        when:
        TransactionValidator validator = new TransactionValidator.Builder()
                .trustStore("src/test/resources/validation-truststore.jks", "foo123", "JKS")
                .build()
        then:
        validator != null
        (validator.validationService as DefaultValidationService).config.getTrustStore() != null
        CommonCertificateVerifier certificateVerifier = ((DefaultValidationService)validator.validationService).getCertificateVerifier() as CommonCertificateVerifier
        certificateVerifier != null
        certificateVerifier.getTrustedCertSources().numberOfCertificates == 13
    }

    def "test overriding earlier config when using shared service instances"(){
        when:
        TransactionValidator validator1 = new TransactionValidator.Builder()
                .trustStore("src/test/resources/validation-truststore.jks", "foo123", "JKS")
                .customValidationPolicy("A-policy")
                .build()
        then:
        validator1 != null
        (validator1.validationService as DefaultValidationService).config.policyName == "A-policy"

        when:
        TransactionValidator validator2 = new TransactionValidator.Builder()
                .trustStore("src/test/resources/validation-truststore.jks", "foo123", "JKS")
                .customValidationPolicy("B-policy")
                .build()
        then:
        validator2 != null
        (validator2.validationService as DefaultValidationService).config.policyName == "B-policy"
        (validator1.validationService as DefaultValidationService).config.policyName == "B-policy"
        validator1.validationService == validator2.validationService
    }

    def "test keeping config separate when using isolated service instances"() {
        when:
        TransactionValidator validator1 = new TransactionValidator.Builder()
                .trustStore("src/test/resources/validation-truststore.jks", "foo123", "JKS")
                .customValidationPolicy("A-policy")
                .buildIsolatedInstance()
        then:
        validator1 != null
        (validator1.validationService as DefaultValidationService).config.policyName == "A-policy"

        when:
        TransactionValidator validator2 = new TransactionValidator.Builder()
                .trustStore("src/test/resources/validation-truststore.jks", "foo123", "JKS")
                .customValidationPolicy("B-policy")
                .buildIsolatedInstance()
        then:
        validator2 != null
        (validator2.validationService as DefaultValidationService).config.policyName == "B-policy"
        (validator1.validationService as DefaultValidationService).config.policyName == "A-policy"
        validator1.validationService != validator2.validationService

        when:
        TransactionValidator validator3 = new TransactionValidator.Builder()
                .trustStore("src/test/resources/validation-truststore.jks", "foo123", "JKS")
                .customValidationPolicy("C-policy")
                .build()
        then:
        validator3 != null
        (validator3.validationService as DefaultValidationService).config.policyName == "C-policy"
        (validator2.validationService as DefaultValidationService).config.policyName == "B-policy"
        (validator1.validationService as DefaultValidationService).config.policyName == "A-policy"
        validator1.validationService != validator3.validationService
        validator2.validationService != validator3.validationService
    }
}
