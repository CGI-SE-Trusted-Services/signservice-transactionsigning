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

import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Basic example of how to use the transaction signature library to
 * sign and validate documents.
 *
 * @author Tobias Agerberg
 */
public class BasicExample {
    public static final void main(String[] args){
        try {
            // Build transaction signer instance to perform document signing
            TransactionSigner signer = new TransactionSigner.Builder()
                    .apiEndpoint("http://localhost:8080/lcso/signRequest/rest/v1")
                    .apiKey("iqxMo5Im4ya2EZsPravicPxj")
                    .signType("rsa2048_sha256")
                    .keyId("key1")
                    .build();

            // Build transaction validator instance to perform document validation
            TransactionValidator validator = new TransactionValidator.Builder()
                    .trustStore("signservice-transactionsigning/src/test/resources/validation-truststore.jks", "foo123", "JKS")
                    .disableRevocationCheck()
                    .build();

            // Prepare a document to be signed.
            Document document = new Document("signservice-transactionsigning/src/test/resources/testdocument.xml");

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
        }
    }
}
