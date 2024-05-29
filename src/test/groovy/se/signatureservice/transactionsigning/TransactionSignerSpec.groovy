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
