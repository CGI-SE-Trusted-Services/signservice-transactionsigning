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

import se.signatureservice.transactionsigning.common.Document
import se.signatureservice.transactionsigning.common.SignedDocument
import spock.lang.Ignore
import spock.lang.Specification

import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore

/**
 * Special test that should be run manually with a remote-sign server up and running.
 *
 * Start remote-sign server in 'development' environment.
 */
@Ignore
class RemoteSignIntegrationSpec extends Specification {
    static String endPoint = "http://localhost:8080/testorg/signRequest/rest/v1"
    static String keyId = "keyId1"
    static String validationTrustStorePath = "src/test/resources/devca_truststore.jks"
    static String validationTrustStorePassword = "foo123"
    static KeyStore validationTrustStore

    def setupSpec() {
        validationTrustStore = KeyStore.getInstance("PKCS12");
        validationTrustStore.load(Files.newInputStream(Path.of(validationTrustStorePath)), validationTrustStorePassword.toCharArray());
    }

    def cleanupSpec() {
    }

    def "Sign and verify #signaturePacking, #signType, #documents"() {
        when:

        TransactionSigner signer = new TransactionSigner.Builder()
                .apiEndpoint(endPoint)
                .signatureAlgorithm("SHA256withRSA")
                .xadESSignaturePacking(signaturePacking)
                .padESSignaturePacking(signaturePacking)
                .cadESSignaturePacking(signaturePacking)
                .signType(signType)
                .keyId(keyId)
                .buildIsolatedInstance()

        TransactionValidator validator = new TransactionValidator.Builder()
                .trustStore(validationTrustStore)
                .disableRevocationCheck()
                .detachedPackaging(signaturePacking == "DETACHED")
                .buildIsolatedInstance()

        List<SignedDocument> signedDocuments = signer.signDocuments(documents)

        for (int i = 0; i < signedDocuments.size(); i++) {
            var signedDocument = signedDocuments.get(i)

            if (signaturePacking == "DETACHED") {
                validator.validateDocument(signedDocument, documents.get(i))
            } else {
                validator.validateDocument(signedDocument)
            }
        }

        then:
        true

        where:
        signaturePacking | signType                     | documents
        "ENVELOPED"      | "signTypeAdes-NO_ROOT"       | [Documents.pdf()]
        "ENVELOPING"     | "signTypeAdes-NO_ROOT"       | [Documents.pdf()]
        "DETACHED"       | "signTypeAdes-NO_ROOT"       | [Documents.pdf()]
        "ENVELOPED"      | "signTypeAdes-NO_ROOT"       | [Documents.xml()]
        "ENVELOPING"     | "signTypeAdes-NO_ROOT"       | [Documents.xml()]
        "DETACHED"       | "signTypeAdes-NO_ROOT"       | [Documents.xml()]
        "ENVELOPING"     | "signTypeAdes-NO_ROOT"       | [Documents.doc()]
        "DETACHED"       | "signTypeAdes-NO_ROOT"       | [Documents.doc()]
        "ENVELOPED"      | "signTypeAdes-NO_ROOT"       | Documents.pdfs()
        "ENVELOPING"     | "signTypeAdes-NO_ROOT"       | Documents.xmls()
        "DETACHED"       | "signTypeAdes-NO_ROOT"       | Documents.docs()
        "ENVELOPED"      | "signTypeAdes-NO_ROOT"       | [Documents.pdf(), Documents.xml()]
        "ENVELOPING"     | "signTypeAdes-NO_ROOT"       | [Documents.xml(), Documents.doc()]
        "DETACHED"       | "signTypeAdes-NO_ROOT"       | [Documents.doc(), Documents.pdf()]

        "ENVELOPED"      | "signTypeAdes-ENTIRE_CHAIN"  | [Documents.xml()]
        "ENVELOPING"     | "signTypeAdes-ENTIRE_CHAIN"  | [Documents.xml()]
        "DETACHED"       | "signTypeAdes-ENTIRE_CHAIN"  | [Documents.xml()]
        "ENVELOPING"     | "signTypeAdes-ENTIRE_CHAIN"  | [Documents.doc()]
        "DETACHED"       | "signTypeAdes-ENTIRE_CHAIN"  | [Documents.doc()]
        "ENVELOPING"     | "signTypeAdes-ENTIRE_CHAIN"  | Documents.xmls()
        "DETACHED"       | "signTypeAdes-ENTIRE_CHAIN"  | Documents.docs()
        "ENVELOPING"     | "signTypeAdes-ENTIRE_CHAIN"  | [Documents.xml(), Documents.doc()]
    }

    static class Documents {

        static Document xml() {
            return new Document("src/test/resources/testdocument.xml");
        }

        static Document pdf() {
            return new Document("src/test/resources/testdocument.pdf");
        }

        static Document doc() {
            return new Document("src/test/resources/testdocument.doc");
        }

        static List<Document> xmls() {
            return List.of(xml(), new Document("src/test/resources/testdocument2.xml"));
        }

        static List<Document> pdfs() {
            return List.of(pdf(), new Document("src/test/resources/testdocument2.pdf"));
        }

        static List<Document> docs() {
            return List.of(doc(), new Document("src/test/resources/testdocument2.doc"));
        }
    }
}