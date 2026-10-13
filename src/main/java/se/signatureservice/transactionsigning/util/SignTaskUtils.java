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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalAccessor;
import java.util.Date;

/**
 * Class containing various helper methods related to
 * signature tasks (SignRequestTask and SignResponseTask).
 *
 * @author Tobias Agerberg
 */
public class SignTaskUtils {
    private static final String NS_ETSI_1_3_2 = "http://uri.etsi.org/01903/v1.3.2#";
    private static final String XADES_SIGNING_TIME = "SigningTime";

    private static final Logger log = LoggerFactory.getLogger(SignTaskUtils.class);
    private static DocumentBuilderFactory documentBuilderFactory;

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

    /**
     * Retrieve Xades signing time from a sign task
     * @param objectData xml data to retrieve xades signing time from
     * @return Signing time in xades object or null if not found
     */
    public static Date getXadesSigningTime(byte[] objectData) {
        Date signingTime = null;

        if(objectData == null){
            return null;
        }

        try {
            org.w3c.dom.Document xadesObject = getSignedInfoDocumentBuilder().parse(new ByteArrayInputStream(objectData));
            NodeList nodeList = xadesObject.getElementsByTagNameNS(NS_ETSI_1_3_2, XADES_SIGNING_TIME);
            if(nodeList.getLength() > 0){
                Element element = (Element)nodeList.item(0);
                signingTime = parseIsoToDate(element.getFirstChild().getTextContent());
            }

            return signingTime;
        } catch (SAXException | IOException | ParserConfigurationException e) {
            log.error("Error parsing signing time from adesObject, {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Parses a String into java.util.Date, accepting both offset and no offset.
     * @return Date
     */
    public static Date parseIsoToDate(String text) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss[.SSS][XXX]");

        TemporalAccessor parsed = formatter.parseBest(
                text,
                OffsetDateTime::from,
                LocalDateTime::from
        );

        Instant instant;
        if (parsed instanceof OffsetDateTime) {
            instant = ((OffsetDateTime) parsed).toInstant();
        } else {
            instant = ((LocalDateTime) parsed)
                    .atZone(ZoneOffset.UTC)
                    .toInstant();
        }

        return Date.from(instant);
    }


    /**
     * Get document builder in order to build SignedInfo and SignedProperties document.
     * DocumentBuilder is not thread safe so we create a new per thread.
     * @return Document builder
     */
    static DocumentBuilder getSignedInfoDocumentBuilder() throws ParserConfigurationException {
        return getSignedInfoDocumentBuilderFactory().newDocumentBuilder();
    }

    /**
     * Get DocumentBuilderFactory to use when creating new instance of
     * DocumentBuilder. This is shared across threads.
     * @return DocumentBuilderFactory
     */
    static DocumentBuilderFactory getSignedInfoDocumentBuilderFactory() {
        if (documentBuilderFactory == null) {
            documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
        }
        return documentBuilderFactory;
    }
}
