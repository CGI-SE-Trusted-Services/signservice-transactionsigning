package se.signatureservice.transactionsigning.util

import spock.lang.Specification

import java.security.cert.X509Certificate

class SignTaskUtilsSpec extends Specification {

    void "test different date formats are understood"(){
        setup:
        def date1 = "2026-02-09T16:12:24.000+01:00"
        def date2 = "2026-02-09T16:12:24.000+00:00"
        def date3 = "2026-02-09T16:12:24.000"
        def date4 = "2026-02-09T16:12:24+01:00"
        def date5 = "2026-02-09T16:12:24"


        when:
        def d1 = SignTaskUtils.parseIsoToDate(date1)
        def d2 = SignTaskUtils.parseIsoToDate(date2)
        def d3 = SignTaskUtils.parseIsoToDate(date3)
        def d4 = SignTaskUtils.parseIsoToDate(date4)
        def d5 = SignTaskUtils.parseIsoToDate(date5)

        then:
        d1 != null
        d2 != null
        d3.toInstant().toEpochMilli() == d2.toInstant().toEpochMilli()
        d4.toInstant().toEpochMilli() == d1.toInstant().toEpochMilli()
        d5.toInstant().toEpochMilli() == d2.toInstant().toEpochMilli()
    }

}
