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
