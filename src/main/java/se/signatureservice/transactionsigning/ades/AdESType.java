/************************************************************************
 *                                                                       *
 *  Signservice Transaction Signing                                      *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.transactionsigning.ades;

import se.signatureservice.transactionsigning.common.MimeType;

/**
 * Class containing definitions of available AdES types to use
 * when specified as request/response attributes.
 *
 * @author Tobias Agerberg
 */
public class AdESType {
    /**
     * XAdES (ETSI TS 101 903)
     */
    public static final String XADES = "xades";

    /**
     * PAdES (ETSI TS 102 778)
     */
    public static final String PADES = "pades";

    /**
     * CAdES (ETSI TS 103 173)
     */
    public static final String CADES = "cades";

    /**
     * Get AdESType to use for a given mime type.
     *
     * @param mimeType Mime type to get AdESType for
     * @return AdESType to use for given mime type.
     */
    public static String fromMimeType(MimeType mimeType){
        if(mimeType == MimeType.XML){
            return AdESType.XADES;
        } else if(mimeType == MimeType.PDF){
            return AdESType.PADES;
        }

        // All other mime types are covered by CAdES.
        return AdESType.CADES;
    }
}
