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

import spock.lang.Specification

import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyStore

class TransactionSignerSpec extends Specification {
    def "test builder using in-memory keystore and truststore"(){
        setup:
        KeyStore keyStore = KeyStore.getInstance("JKS")
        Files.newInputStream(Paths.get("src/test/resources/keystore.jks")).withCloseable { keyStoreStream ->
            keyStore.load(keyStoreStream, "TSWCeC".toCharArray())
        }

        KeyStore trustStore = KeyStore.getInstance("JKS")
        Files.newInputStream(Paths.get("src/test/resources/truststore.jks")).withCloseable { trustStoreStream ->
            trustStore.load(trustStoreStream, "foo123".toCharArray())
        }

        when:
        TransactionSigner signer = new TransactionSigner.Builder()
                .apiEndpoint("http://192.168.99.21:8080/lcso/signRequest/rest/v1")
                .signType("rsa2048_sha256")
                .keyId("remotesign_st")
                .sslKeyStore(keyStore, "TSWCeC")
                .sslTrustStore(trustStore)
                .build()

        then:
        signer != null
        signer.config.getSslKeyStore() != null
        signer.config.getSslKeyStore().getKey("8af76eae8e1a201;cn=mock issuing ca,o=mockasiner ab,c=se", "TSWCeC".toCharArray()) != null
        signer.config.getSslTrustStore() != null
    }

    def "test builder using file-based keystore and truststore"(){
        when:
        TransactionSigner signer = new TransactionSigner.Builder()
                .apiEndpoint("http://192.168.99.21:8080/lcso/signRequest/rest/v1")
                .signType("rsa2048_sha256")
                .keyId("remotesign_st")
                .sslKeyStore("src/test/resources/keystore.jks", "TSWCeC", "JKS")
                .sslTrustStore("src/test/resources/truststore.jks", "foo123", "JKS")
                .build()
        then:
        signer != null
        signer.config.getSslKeyStore() != null
        signer.config.getSslKeyStore().getKey("8af76eae8e1a201;cn=mock issuing ca,o=mockasiner ab,c=se", "TSWCeC".toCharArray()) != null
        signer.config.getSslTrustStore() != null
    }
}
