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
package se.signatureservice.transactionsigning.example;

import se.signatureservice.transactionsigning.TransactionSigner;
import se.signatureservice.transactionsigning.TransactionValidator;
import se.signatureservice.transactionsigning.common.*;

/**
 * Example of how to use the transaction signature library, with independently
 * configured TransactionSigner and TransactionValidator instances,
 * to sign and validate documents.
 *
 * @author Fredrik
 */
public class MultipleInstancesExample {
    public static void main(String[] args){
        try {
            // Build transaction signer instance to perform document signing
            TransactionSigner signer1 = new TransactionSigner.Builder()
                    .apiEndpoint("http://localhost:8080/lcso/signRequest/rest/v1")
                    .apiKey("iqxMo5Im4ya2EZsPravicPxj")
                    .signType("rsa2048_sha256")
                    .keyId("key1")
                    .buildIsolatedInstance();

            // Build another one with different configuration
            TransactionSigner signer2 = new TransactionSigner.Builder()
                    .apiEndpoint("http://localhost:8080/lcso/signRequest/rest/v1")
                    .apiKey("iqxMo5Im4ya2EZsPravicPxj")
                    .signType("rsa2048_sha256")
                    .keyId("key2")
                    .xadESSignatureLevel("XAdES-BASELINE-LTA")
                    .buildIsolatedInstance();


            // Build transaction validator instance to perform document validation
            TransactionValidator validator1 = new TransactionValidator.Builder()
                    .trustStore("signservice-transactionsigning/src/test/resources/validation-truststore.jks", "foo123", "JKS")
                    .disableRevocationCheck()
                    .buildIsolatedInstance();

            // Build another one with different configuration
            TransactionValidator validator2 = new TransactionValidator.Builder()
                    .trustStore("signservice-transactionsigning/src/test/resources/validation-truststore.jks", "foo123", "JKS")
                    .customValidationPolicy("anotherPolicy.xml")
                    .buildIsolatedInstance();

            // Prepare a document to be signed.
            Document document = new Document("signservice-transactionsigning/src/test/resources/testdocument.xml");

            // Use transaction signer to sign the document.
            System.out.println("Signing document...");
            SignedDocument signedDocument1 = signer1.signDocument(document);
            SignedDocument signedDocument2 = signer2.signDocument(document);
            System.out.println("Document signed successfully!");

            // Use transaction validator to validate the signed document.
            System.out.println("Validating signed documents...");
            validator1.validateDocument(signedDocument1);
            validator2.validateDocument(signedDocument2);
            System.out.println("Documents validated successfully!");

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
        }
    }
}
