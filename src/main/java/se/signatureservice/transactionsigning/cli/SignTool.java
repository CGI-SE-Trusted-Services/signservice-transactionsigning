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
package se.signatureservice.transactionsigning.cli;

import se.signatureservice.transactionsigning.TransactionSigner;
import se.signatureservice.transactionsigning.TransactionValidator;
import se.signatureservice.transactionsigning.common.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;

/**
 * Commandline tool to perform remote signatures using the transaction
 * signature library. Mainly used to test basic functionality.
 *
 * Configuration through environment variables or JVM parameters:
 * <pre>
 * -- SIGN --
 * TS_APIENDPOINT         : URL to API endpoint to use.
 * TS_SIGNTYPE            : Signature type to request/use.
 * TS_KEYID               : Key ID to request/use.
 * TS_KEYSTORE            : Keystore to use for client authentication.
 * TS_KEYSTORE_PASSWORD   : Password protecting the keystore.
 * TS_KEYSTORE_TYPE       : Type of keystore (optional, default is "JKS")
 * TS_TRUSTSTORE          : Truststore to use when validating server.
 * TS_TRUSTSTORE_PASSWORD : Password protecting the truststore.
 * TS_TRUSTSTORE_TYPE     : Type of truststore (optional, default is "JKS")
 * TS_APIKEY              : API Key to use for authentication (optional)
 * TS_SIGNATUREALGORITHM  : Signature algorithm to use when signing documents (optional, default is "SHA512withRSAandMGF1")
 *
 * -- VERIFY --
 * TS_TRUSTSTORE          : Truststore to use when validating documents.
 * TS_TRUSTSTORE_PASSWORD : Password protecting the truststore.
 * TS_TRUSTSTORE_TYPE     : Type of truststore (optional, default is "JKS")
 * TS_ENABLE_REVOCATION   : Set to "true" to enable revocation check.
 *
 * Sign Usage:
 * SignTool sign [document to sign] [output path]
 *
 * [document to sign]     : Path to document to sign.
 * [output path]          : Path to write signed document to (optional).
 *
 * Verify Usage:
 * SignTool verify [document to verify]
 *
 * [document to verify]   : Path to document to verify.
 * </pre>
 * @author Tobias Agerberg
 */
public class SignTool {
    private static final String ENV_TS_APIENDPOINT = "TS_APIENDPOINT";
    private static final String ENV_TS_APIKEY = "TS_APIKEY";
    private static final String ENV_TS_SIGNTYPE = "TS_SIGNTYPE";
    private static final String ENV_TS_KEYID = "TS_KEYID";
    private static final String ENV_TS_KEYSTORE = "TS_KEYSTORE";
    private static final String ENV_TS_KEYSTORE_PASSWORD = "TS_KEYSTORE_PASSWORD";
    private static final String ENV_TS_KEYSTORE_TYPE = "TS_KEYSTORE_TYPE";
    private static final String ENV_TS_TRUSTSTORE = "TS_TRUSTSTORE";
    private static final String ENV_TS_TRUSTSTORE_PASSWORD = "TS_TRUSTSTORE_PASSWORD";
    private static final String ENV_TS_TRUSTSTORE_TYPE = "TS_TRUSTSTORE_TYPE";
    private static final String ENV_TS_ENABLE_REVOCATION = "TS_ENABLE_REVOCATION";
    private static final String ENV_TS_SIGNATUREALGORITHM = "TS_SIGNATUREALGORITHM";

    private static final String ENV_TS_CADES_SIGNATURELEVEL = "TS_CADES_SIGNATURELEVEL";
    private static final String ENV_TS_CADES_SIGNATUREPACKING = "TS_CADES_SIGNATUREPACKING";
    private static final String ENV_TS_PADES_SIGNATURELEVEL = "TS_PADES_SIGNATURELEVEL";
    private static final String ENV_TS_PADES_SIGNATUREPACKING = "TS_PADES_SIGNATUREPACKING";
    private static final String ENV_TS_XADES_SIGNATURELEVEL = "TS_XADES_SIGNATURELEVEL";
    private static final String ENV_TS_XADES_SIGNATUREPACKING = "TS_XADES_SIGNATUREPACKING";
    private static final String ENV_TS_XADES_SIGNEDINFO_CANONICALIZATION = "TS_XADES_SIGNEDINFO_CANONICALIZATION";
    private static final String ENV_TS_XADES_SIGNEDPROPERTIES_CANONICALIZATION = "TS_XADES_SIGNEDPROPERTIES_CANONICALIZATION";
    private static final String ENV_TS_XADES_XPATH_LOCATION = "TS_XADES_XPATH_LOCATION";

    private static final String CMD_SIGN = "sign";
    private static final String CMD_VERIFY = "verify";

    /**
     * Read configuration from JVM parameter or environment.
     * @param key Configuration key to read.
     * @return Value for the given key, never null.
     * @throws InvalidConfigurationException If configuration did not exist.
     */
    private static String getConfig(String key) throws InvalidConfigurationException {
        String value = getConfig(key, null);
        if(value == null){
            throw new InvalidConfigurationException("Missing required configuration (" + key + "). " +
                    "Please set this as either a JVM parameter or environment variable.");
        }
        return value;
    }

    /**
     * Read configuration from JVM parameter or environment.
     * @param key key Configuration key to read.
     * @param defaultValue default value to return if key is not available.
     * @return Value for given key or default value if not defined.
     */
    private static String getConfig(String key, String defaultValue){
        String value = System.getProperty(key);
        if(value == null){
            value = System.getenv(key);
        }
        return value != null ? value : defaultValue;
    }

    private static void printUsage(){
        System.out.println("Commandline tool to perform remote signatures using the transaction");
        System.out.println("signature library. Mainly used to test basic functionality.");
        System.out.println();
        System.out.println("Configuration through environment variables or JVM parameters:");
        System.out.println();
        System.out.println("-- SIGN --");
        System.out.println(ENV_TS_APIENDPOINT + "         : URL to API endpoint to use.");
        System.out.println(ENV_TS_SIGNTYPE + "            : Signature type to request/use.");
        System.out.println(ENV_TS_KEYID + "               : Key ID to request/use.");
        System.out.println(ENV_TS_KEYSTORE + "            : Keystore to use for client authentication.");
        System.out.println(ENV_TS_KEYSTORE_PASSWORD + "   : Password protecting the keystore.");
        System.out.println(ENV_TS_KEYSTORE_TYPE + "       : Type of keystore (optional, default is \"JKS\")");
        System.out.println(ENV_TS_TRUSTSTORE + "          : Truststore to use when validating server.");
        System.out.println(ENV_TS_TRUSTSTORE_PASSWORD + " : Password protecting the truststore.");
        System.out.println(ENV_TS_TRUSTSTORE_TYPE + "     : Type of truststore (optional, default is \"JKS\")");
        System.out.println(ENV_TS_APIKEY + "              : API Key to use for authentication (optional)");
        System.out.println(ENV_TS_SIGNATUREALGORITHM + "  : Signature algorithm to use when signing documents (optional, default is \"SHA512withRSAandMGF1\").");
        System.out.println();
        System.out.println("-- VERIFY --");
        System.out.println(ENV_TS_TRUSTSTORE + "          : Truststore to use when validating documents.");
        System.out.println(ENV_TS_TRUSTSTORE_PASSWORD + " : Password protecting the truststore.");
        System.out.println(ENV_TS_TRUSTSTORE_TYPE + "     : Type of truststore (optional, default is \"JKS\")");
        System.out.println(ENV_TS_ENABLE_REVOCATION + "   : Set to \"true\" to enable revocation check.");
        System.out.println();
        System.out.println("Sign Usage:");
        System.out.println("SignTool sign <document to sign> [output path]");
        System.out.println();
        System.out.println("<document to sign>     : Path to document to sign.");
        System.out.println("[output path]          : Path to write signed document to (optional).");
        System.out.println();
        System.out.println("Verify Usage:");
        System.out.println("SignTool verify <document to verify>");
        System.out.println();
        System.out.println("<document to verify>   : Path to document to verify.");
    }

    /**
     * Verify that a file exists and can be read.
     * @param filePath File path to verify
     * @throws InvalidParameterException If file does not exist or cannot be read.
     */
    private static void verifyDocument(String filePath) throws InvalidParameterException {
        File file = null;
        if(filePath != null){
            file = new File(filePath);
        }

        if(file == null || !file.exists() || !file.canRead()){
            throw new InvalidParameterException("Cannot read file (" + filePath + ").");
        }
    }

    public static void main(String[] args){
        try {
            if(args.length < 2){
                printUsage();
                return;
            }

            String command = args[0];
            if(command.equalsIgnoreCase(CMD_SIGN)){
                // Build transaction signer instance to perform document signing
                TransactionSigner.Builder transactionSignerBuilder = new TransactionSigner.Builder()
                        .apiEndpoint(getConfig(ENV_TS_APIENDPOINT))
                        .signType(getConfig(ENV_TS_SIGNTYPE))
                        .keyId(getConfig(ENV_TS_KEYID));

                String apiKey = getConfig(ENV_TS_APIKEY, null);
                if(apiKey != null){
                    transactionSignerBuilder.apiKey(apiKey);
                }

                String keyStorePath = getConfig(ENV_TS_KEYSTORE, null);
                String keyStorePassword = getConfig(ENV_TS_KEYSTORE_PASSWORD, null);
                String keyStoreType = getConfig(ENV_TS_KEYSTORE_TYPE, "JKS");
                String trustStorePath = getConfig(ENV_TS_TRUSTSTORE, null);
                String trustStorePassword = getConfig(ENV_TS_TRUSTSTORE_PASSWORD, null);
                String trustStoreType = getConfig(ENV_TS_TRUSTSTORE_TYPE, "JKS");

                if(keyStorePath != null && keyStorePassword != null){
                    System.out.println("Using SSL Keystore: " + keyStorePath);
                    KeyStore keyStore = KeyStore.getInstance(keyStoreType);
                    keyStore.load(Files.newInputStream(Paths.get(keyStorePath)), keyStorePassword.toCharArray());
                    transactionSignerBuilder.sslKeyStore(keyStore, keyStorePassword);
                }

                if(trustStorePath != null && trustStorePassword != null){
                    System.out.println("Using validation truststore: " + trustStorePath);
                    KeyStore trustStore = KeyStore.getInstance(trustStoreType);
                    trustStore.load(Files.newInputStream(Paths.get(trustStorePath)), trustStorePassword.toCharArray());
                    transactionSignerBuilder.sslTrustStore(trustStore);
                }

                String signatureAlgorithm = getConfig(ENV_TS_SIGNATUREALGORITHM, null);
                if(signatureAlgorithm != null){
                    System.out.println("Using signature algorithm: " + signatureAlgorithm);
                    transactionSignerBuilder.signatureAlgorithm(signatureAlgorithm);
                }

                String cadesSignatureLevel = getConfig(ENV_TS_CADES_SIGNATURELEVEL, null);
                if(cadesSignatureLevel != null){
                    System.out.println("Using Cades Signature Level: " + cadesSignatureLevel);
                    transactionSignerBuilder.cadESSignatureLevel(cadesSignatureLevel);
                }

                String cadesSignaturePacking = getConfig(ENV_TS_CADES_SIGNATUREPACKING, null);
                if (cadesSignaturePacking != null) {
                    System.out.println("Using Cades Signature Packing: " + cadesSignaturePacking);
                    transactionSignerBuilder.cadESSignaturePacking(cadesSignaturePacking);
                }

                String padesSignatureLevel = getConfig(ENV_TS_PADES_SIGNATURELEVEL, null);
                if (padesSignatureLevel != null) {
                    System.out.println("Using Pades Signature Level: " + padesSignatureLevel);
                    transactionSignerBuilder.padESSignatureLevel(padesSignatureLevel);
                }

                String padesSignaturePacking = getConfig(ENV_TS_PADES_SIGNATUREPACKING, null);
                if (padesSignaturePacking != null) {
                    System.out.println("Using Pades Signature Packing: " + padesSignaturePacking);
                    transactionSignerBuilder.padESSignaturePacking(padesSignaturePacking);
                }

                String xadesSignatureLevel = getConfig(ENV_TS_XADES_SIGNATURELEVEL, null);
                if (xadesSignatureLevel != null) {
                    System.out.println("Using Xades Signature Level: " + xadesSignatureLevel);
                    transactionSignerBuilder.xadESSignatureLevel(xadesSignatureLevel);
                }

                String xadesSignaturePacking = getConfig(ENV_TS_XADES_SIGNATUREPACKING, null);
                if (xadesSignaturePacking != null) {
                    System.out.println("Using Xades Signature Packing: " + xadesSignaturePacking);
                    transactionSignerBuilder.xadESSignaturePacking(xadesSignaturePacking);
                }

                String xadesSignedInfoCanonicalizationMethod = getConfig(ENV_TS_XADES_SIGNEDINFO_CANONICALIZATION, null);
                if (xadesSignedInfoCanonicalizationMethod != null) {
                    System.out.println("Using Xades SignedInfo Canonicalization Method: " + xadesSignedInfoCanonicalizationMethod);
                    transactionSignerBuilder.xadESSignedInfoCanonicalizationMethod(xadesSignedInfoCanonicalizationMethod);
                }

                String xadesSignedPropertiesCanonicalizationMethod = getConfig(ENV_TS_XADES_SIGNEDPROPERTIES_CANONICALIZATION, null);
                if (xadesSignedPropertiesCanonicalizationMethod != null) {
                    System.out.println("Using Xades SignedProperties Canonicalization Method: " + xadesSignedPropertiesCanonicalizationMethod);
                    transactionSignerBuilder.xadESSignedPropertiesCanonicalizationMethod(xadesSignedPropertiesCanonicalizationMethod);
                }

                String xadesXPathLocation = getConfig(ENV_TS_XADES_XPATH_LOCATION, null);
                if (xadesXPathLocation != null) {
                    System.out.println("Using Xades XPath Location: " + xadesXPathLocation);
                    transactionSignerBuilder.xadESXPathLocationString(xadesXPathLocation);
                }

                TransactionSigner signer = transactionSignerBuilder.build();

                // Prepare a document to be signed.
                String pathName = args[1];
                verifyDocument(pathName);
                Document document = new Document(pathName);

                // Use transaction signer to sign the document.
                System.out.println("Signing document...");
                SignedDocument signedDocument = signer.signDocument(document);
                System.out.println("Document signed successfully!");

                if (signedDocument == null || signedDocument.getName() == null) {
                    throw new SignatureException("Signed document or its name is null");
                }

                String parentPath = new File(pathName).getParent();
                String outputPath = (parentPath != null ? (parentPath + "/") : "") + "signed_" + signedDocument.getName();
                if(args.length > 2){
                    outputPath = args[2];
                }

                // Store/process signed document
                try (FileOutputStream outStream = new FileOutputStream(outputPath)) {
                    outStream.write(signedDocument.getContent());
                }

            } else if(command.equalsIgnoreCase(CMD_VERIFY)){
                String trustStorePath = getConfig(ENV_TS_TRUSTSTORE, null);
                String trustStorePassword = getConfig(ENV_TS_TRUSTSTORE_PASSWORD, null);
                String trustStoreType = getConfig(ENV_TS_TRUSTSTORE_TYPE, "JKS");

                // Build transaction validator instance to perform document validation
                TransactionValidator.Builder transactionValidatorBuilder = new TransactionValidator.Builder();

                if(trustStorePath != null && trustStorePassword != null){
                    System.out.println("Using validation truststore: " + trustStorePath);
                    KeyStore validationTrustStore = KeyStore.getInstance(trustStoreType);
                    validationTrustStore.load(Files.newInputStream(Paths.get(trustStorePath)), trustStorePassword.toCharArray());
                    transactionValidatorBuilder.trustStore(validationTrustStore);
                }

                String enableRevocation = getConfig(ENV_TS_ENABLE_REVOCATION, null);
                if(enableRevocation == null || !enableRevocation.equalsIgnoreCase("true")){
                    transactionValidatorBuilder.disableRevocationCheck();
                }

                TransactionValidator validator = transactionValidatorBuilder.build();

                // Prepare document to verify
                String pathName = args[1];
                verifyDocument(pathName);
                SignedDocument signedDocument = new SignedDocument(pathName);

                // Use transaction validator to validate the signed document.
                System.out.println("Validating signed document...");
                validator.validateDocument(signedDocument);
                System.out.println("Document validated successfully!");

            } else {
                System.err.println("Unknown command (" + command + ")");
                printUsage();
            }

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
