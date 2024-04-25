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
package se.signatureservice.transactionsigning.util;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Class containing various helper methods related to
 * signature tasks (SignRequestTask and SignResponseTask).
 *
 * @author Tobias Agerberg
 */
public class SignTaskUtils {

    /**
     * Get attribute from signature response JSON object.
     *
     * @param signResponse Signature response object to get attribute from
     * @param attributeKey Attribute key to read
     * @return Attribute value as String or null if attribute was not available.
     */
    public static String getResponseAttribute(JSONObject signResponse, String attributeKey) {
        String attributeValue;
        try {
            attributeValue = signResponse.getJSONObject("attributes").getString(attributeKey);
        } catch(JSONException e){
            attributeValue = null;
        }

        return attributeValue;
    }

    /**
     * Get binary attribute from signature response JSON object. The binary
     * attribute is expected to be Base64-encoded in the JSON object.
     *
     * @param signResponse Signature response object to get attribute from
     * @param attributeKey Attribute key to read
     * @return Attribute value as byte[] or null if attribute was not available.
     */
    public static byte[] getBinaryResponseAttribute(JSONObject signResponse, String attributeKey){
        byte[] attributeValue = null;
        String encodedAttributeValue = getResponseAttribute(signResponse, attributeKey);
        if(encodedAttributeValue != null){
            try {
                attributeValue = Base64.decode(encodedAttributeValue);
            } catch(DecoderException ignored){
            }
        }
        return attributeValue;
    }
}
