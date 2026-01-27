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

import se.signatureservice.transactionsigning.signservice.DefaultSignService
import se.signatureservice.transactionsigning.supportservice.DefaultSupportService
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
        (signer.signService as DefaultSignService).config.getSslKeyStore() != null
        (signer.signService as DefaultSignService).config.getSslKeyStore().getKey("8af76eae8e1a201;cn=mock issuing ca,o=mockasiner ab,c=se", "TSWCeC".toCharArray()) != null
        (signer.signService as DefaultSignService).config.getSslTrustStore() != null
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
        (signer.signService as DefaultSignService).config.getSslKeyStore() != null
        (signer.signService as DefaultSignService).config.getSslKeyStore().getKey("8af76eae8e1a201;cn=mock issuing ca,o=mockasiner ab,c=se", "TSWCeC".toCharArray()) != null
        (signer.signService as DefaultSignService).config.getSslTrustStore() != null
    }

    def "test overriding earlier config when using shared service instances"() {
        when:
        TransactionSigner signer1 = new TransactionSigner.Builder()
                .apiEndpoint("http://192.168.99.21:8080/lcso/signRequest/rest/v1")
                .signType("rsa2048_sha256")
                .keyId("remotesign_st")
                .sslKeyStore("src/test/resources/keystore.jks", "TSWCeC", "JKS")
                .sslTrustStore("src/test/resources/truststore.jks", "foo123", "JKS")
                .xadESSignatureLevel("A-level")
                .build()

        then:
        signer1 != null
        (signer1.supportService as DefaultSupportService).config.xadesSignatureLevel == "A-level"


        when:
        TransactionSigner signer2 = new TransactionSigner.Builder()
                .apiEndpoint("http://192.168.99.21:8080/lcso/signRequest/rest/v1")
                .signType("rsa2048_sha256")
                .keyId("remotesign_st")
                .sslKeyStore("src/test/resources/keystore.jks", "TSWCeC", "JKS")
                .sslTrustStore("src/test/resources/truststore.jks", "foo123", "JKS")
                .xadESSignatureLevel("B-level")
                .build()

        then:
        signer2 != null
        (signer2.supportService as DefaultSupportService).config.xadesSignatureLevel == "B-level"
        (signer1.supportService as DefaultSupportService).config.xadesSignatureLevel == "B-level"
        signer1.supportService == signer2.supportService
        signer1.signService == signer2.signService
    }

    def "test keeping config separate when using isolated service instances"() {
        when:
        TransactionSigner signer1 = new TransactionSigner.Builder()
                .apiEndpoint("http://192.168.99.21:8080/lcso/signRequest/rest/v1")
                .signType("rsa2048_sha256")
                .keyId("remotesign_st")
                .sslKeyStore("src/test/resources/keystore.jks", "TSWCeC", "JKS")
                .sslTrustStore("src/test/resources/truststore.jks", "foo123", "JKS")
                .xadESSignatureLevel("A-level")
                .buildIsolatedInstance()

        then:
        signer1 != null
        (signer1.supportService as DefaultSupportService).config.xadesSignatureLevel == "A-level"


        when:
        TransactionSigner signer2 = new TransactionSigner.Builder()
                .apiEndpoint("http://192.168.99.21:8080/lcso/signRequest/rest/v1")
                .signType("rsa2048_sha256")
                .keyId("remotesign_st")
                .sslKeyStore("src/test/resources/keystore.jks", "TSWCeC", "JKS")
                .sslTrustStore("src/test/resources/truststore.jks", "foo123", "JKS")
                .xadESSignatureLevel("B-level")
                .buildIsolatedInstance()

        then:
        signer2 != null
        (signer2.supportService as DefaultSupportService).config.xadesSignatureLevel == "B-level"
        (signer1.supportService as DefaultSupportService).config.xadesSignatureLevel == "A-level"
        signer1.supportService != signer2.supportService
        signer1.signService != signer2.signService

        when:
        TransactionSigner signer3 = new TransactionSigner.Builder()
                .apiEndpoint("http://192.168.99.21:8080/lcso/signRequest/rest/v1")
                .signType("rsa2048_sha256")
                .keyId("remotesign_st")
                .sslKeyStore("src/test/resources/keystore.jks", "TSWCeC", "JKS")
                .sslTrustStore("src/test/resources/truststore.jks", "foo123", "JKS")
                .xadESSignatureLevel("C-level")
                .build()

        then:
        signer3 != null
        (signer3.supportService as DefaultSupportService).config.xadesSignatureLevel == "C-level"
        (signer2.supportService as DefaultSupportService).config.xadesSignatureLevel == "B-level"
        (signer1.supportService as DefaultSupportService).config.xadesSignatureLevel == "A-level"
        signer1.supportService != signer3.supportService
        signer1.signService != signer3.signService
        signer2.supportService != signer3.supportService
        signer2.signService != signer3.signService
    }
}
