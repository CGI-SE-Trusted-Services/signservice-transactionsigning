package se.signatureservice.transactionsigning.util

import spock.lang.Specification

import java.security.cert.X509Certificate

class CommonUtilsSpec extends Specification {
    void "test getCertfromByteArray"(){
        setup:
        byte[] certData = this.class.getResourceAsStream("/testcert.pem").bytes

        when:
        X509Certificate cert = CommonUtils.getCertfromByteArray(certData)

        then:
        cert.subjectDN.name == "O=Logica SE IM Certificate Service ST, CN=testkey"
        cert.issuerDN.name == "O=Logica SE IM Certificate Service ST, CN=Logica SE IM Certificate Service ST ServerCA v2"
    }

    void "test getBytesFromInputStream"(){
        when:
        byte[] data1 = CommonUtils.getBytesFromInputStream(this.class.getResourceAsStream("/testcert.pem"))
        byte[] data2 = this.class.getResourceAsStream("/testcert.pem").bytes

        then:
        data1 == data2
    }
}
