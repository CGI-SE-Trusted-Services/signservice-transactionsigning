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
package se.signatureservice.transactionsigning.signservice;

import se.signatureservice.transactionsigning.SignerConfig;
import se.signatureservice.transactionsigning.common.InvalidConfigurationException;
import se.signatureservice.transactionsigning.common.InvalidParameterException;
import se.signatureservice.transactionsigning.common.SignatureException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * Implementation of a remote signing service.
 *
 * @author Tobias Agerberg.
 */
public class DefaultSignService implements SignService {
    private static final Logger log = LoggerFactory.getLogger(DefaultSignService.class);

    private SignerConfig config;
    private boolean initialized;
    private SSLContext sslContext;

    public DefaultSignService(){
        initialized = false;
    }

    /**
     * Initialize the support service instance.
     *
     * @param config Configuration to use for the support service instance.
     * @throws InvalidConfigurationException If an error occurred when initializing due to invalid configuration.
     */
    public void init(SignerConfig config) throws InvalidConfigurationException {
        this.config = config;

        if(config.getApiEndpoint() == null){
            throw new InvalidConfigurationException("API endpoint is missing");
        }

        if(config.getSslKeyStore() != null){
            sslContext = createSSLContext(config.getSslKeyStore(), config.getSslKeyStorePassword(), config.getSslTrustStore(), config.getSslAlgorithm());
        } else {
            sslContext = null;
        }

        initialized = true;
    }

    /**
     * Send signature request to obtain a signature response.
     *
     * @param signRequest Signature request in JSON format.
     * @return Signature response in JSON format.
     * @throws SignatureException If an error occurred during signature request.
     */
    public String requestSignature(String signRequest) throws SignatureException {
        String response = null;
        HttpURLConnection connection = null;

        if(!initialized){
            throw new SignatureException("SignService must be initialized before calling requestSignature");
        }

        try {
            URL url = new URL(config.getApiEndpoint());
            if(url.getProtocol().equalsIgnoreCase("https")){
                connection = (HttpsURLConnection)url.openConnection();

                if(sslContext != null){
                    ((HttpsURLConnection)connection).setSSLSocketFactory(sslContext.getSocketFactory());
                }
            } else {
                connection = (HttpURLConnection) url.openConnection();
            }

            connection.setDoOutput(true);
            connection.setInstanceFollowRedirects(false);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            if(config.getApiKey() != null) {
                connection.setRequestProperty("Authorization", "bearer " + config.getApiKey());
            }
            OutputStream os = connection.getOutputStream();
            os.write(signRequest.getBytes("UTF-8"));
            os.close();
            connection.getResponseCode();

            BufferedReader reader;
            if (connection.getResponseCode() >= 200 && connection.getResponseCode() <= 299) {
                reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            } else {
                reader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
            }

            String line;
            StringBuilder buffer = new StringBuilder();
            while((line = reader.readLine()) != null){
                buffer.append(line);
            }

            try {
                response = new JSONObject(buffer.toString()).toString();
            } catch(Exception e){
                log.error("Invalid response received from server: " + buffer);
            }
            connection.disconnect();

        } catch(Exception e) {
            throw new SignatureException("Error when requesting signature: "+ e.getMessage(), e);
        } finally {
            if(connection != null){
                connection.disconnect();
            }
        }

        return response;
    }

    /**
     * Create SSL Context for client certificate authentication.
     *
     * @param keyStore Key store containing certificate and private key for client authentication.
     * @param keystorePassword Password that protects the key store.
     * @param trustStore Trust store containing trusted issuers for SSL server certificates, or null to use default JRE trust store.
     * @param sslAlgorithm Algorithm to use.
     * @return SSL context initialized with given parameters.
     */
    private SSLContext createSSLContext(KeyStore keyStore, String keystorePassword, KeyStore trustStore, String sslAlgorithm){
        SSLContext context = null;

        try {
            context = SSLContext.getInstance(sslAlgorithm);

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, keystorePassword.toCharArray());
            KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

            TrustManager[] trustManagers = null;
            if (trustStore != null) {
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(trustStore);
                trustManagers = trustManagerFactory.getTrustManagers();
            }

            context.init(keyManagers, trustManagers, null);
        } catch(Exception e){
            log.error("Failed to create SSL context: " + e.getMessage(), e);
        }

        return context;
    }

    /**
     * Load keystore from path that exists on either classpath or filesystem.
     * @param path Path to keystore on classpath or filesystem.
     * @param password Password that protects the keystore
     * @param type Type of keystore to use or null to use the default.
     * @return KeyStore loaded from given path.
     * @throws KeyStoreException If an error occurred when initializing the keystore
     * @throws CertificateException If a certificate error occured when reading the keystore
     * @throws NoSuchAlgorithmException If an algorithm error occurred when reading the keystore
     * @throws IOException If error occured while reading keystore data
     * @throws InvalidParameterException If keystore could not be read with given parameters
     */
    private KeyStore loadKeyStore(String path, String password, String type) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, InvalidParameterException {
        KeyStore keyStore = KeyStore.getInstance(type != null ? type : KeyStore.getDefaultType());
        File keyStoreFile = new File(path);
        InputStream keyStoreResource = this.getClass().getClassLoader().getResourceAsStream(path);

        if(keyStoreResource != null){
            log.debug("Loading from classpath: " + path);
            keyStore.load(keyStoreResource, password.toCharArray());
        } else if(keyStoreFile != null && keyStoreFile.exists()){
            log.debug("Loading from file system: " + path);
            keyStore.load(new FileInputStream(keyStoreFile), password.toCharArray());
        } else {
            throw new InvalidParameterException("Cannot read keystore (" + path + ") from classpath or filesystem.");
        }
        return keyStore;
    }

}
