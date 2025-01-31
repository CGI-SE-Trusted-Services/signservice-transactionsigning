package se.signatureservice.transactionsigning

import eu.europa.esig.dss.validation.CommonCertificateVerifier
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
        validator.config.getTrustStore() != null
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
        validator.config.getTrustStore() != null
        CommonCertificateVerifier certificateVerifier = ((DefaultValidationService)validator.validationService).getCertificateVerifier() as CommonCertificateVerifier
        certificateVerifier != null
        certificateVerifier.getTrustedCertSources().numberOfCertificates == 13
    }
}
