/************************************************************************
 *                                                                       *
 *  Certificate Service - Remote Sign                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.transactionsigning.example;

import se.signatureservice.transactionsigning.TransactionSigner;
import se.signatureservice.transactionsigning.TransactionValidator;
import se.signatureservice.transactionsigning.common.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;

/**
 * Example of how to use the transaction signature library to
 * sign and validate documents, using custom keystore, truststore
 * and validation truststore.
 *
 * @author Tobias Agerberg
 */
public class CustomKeyStoreExample {
    public static final void main(String[] args){
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(new File("src/test/resources/keystore.jks")), "TSWCeC".toCharArray());
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(new File("src/test/resources/truststore.jks")), "foo123".toCharArray());
            KeyStore validationTrustStore = KeyStore.getInstance("JKS");
            validationTrustStore.load(new FileInputStream(new File("src/test/resources/validation-truststore.jks")), "foo123".toCharArray());

            // Build transaction signer instance to perform document signing
            TransactionSigner signer = new TransactionSigner.Builder()
                    .apiEndpoint("https://localhost:8443/lcso/signRequest/rest/v1")
                    .sslKeyStore(keyStore, "TSWCeC")
                    .sslTrustStore(trustStore)
                    .signType("rsa2048_sha256")
                    .keyId("key1")
                    .build();

            // Build transaction validator instance to perform document validation
            TransactionValidator validator = new TransactionValidator.Builder()
                    .trustStore(validationTrustStore)
                    .disableRevocationCheck()
                    .build();

            // Prepare a document to be signed.
            Document document = new Document("src/test/resources/testdocument.xml");

            // Use transaction signer to sign the document.
            System.out.println("Signing document...");
            SignedDocument signedDocument = signer.signDocument(document);
            System.out.println("Document signed successfully!");

            // Use transaction validator to validate the signed document.
            System.out.println("Validating signed document...");
            validator.validateDocument(signedDocument);
            System.out.println("Document validated successfully!");

            // Store/process signed document
            FileOutputStream outStream = new FileOutputStream("/tmp/signed_" + signedDocument.getName());
            outStream.write(signedDocument.getContent());
            outStream.close();

        } catch(SignatureException e){
            System.err.println("Transaction signature error occurred: " + e.getMessage());
        } catch(SignatureIOException e){
            System.err.println("I/O error occurred when performing transaction signature: " + e.getMessage());
        } catch(ValidationException e){
            System.err.println("Signature is not valid: " + e.getMessage());
        } catch(ValidationIOException e){
            System.err.println("I/O error occurred when performing signature validation: " + e.getMessage());
        } catch(InvalidConfigurationException e){
            System.err.println("Error occurred due to invalid configuration: " + e.getMessage());
        } catch(InvalidParameterException e){
            System.err.println("Error occurred due to invalid parameters: " + e.getMessage());
        } catch(IOException e){
            System.err.println("I/O error occurred when storing signed document: " + e.getMessage());
        } catch(Exception e){
            System.err.println("Error occurred: " + e.getMessage());
        }
    }
}
