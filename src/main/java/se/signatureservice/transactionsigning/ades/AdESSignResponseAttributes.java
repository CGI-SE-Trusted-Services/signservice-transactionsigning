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

/**
 * Class that contains attributes used in SignResponseTask for
 * AdES (Advanced Electronic Signature) requests.
 *
 * @author Tobias Agerberg
 */
public class AdESSignResponseAttributes {
    /**
     * Attribute containing the updated signature data that contains
     * the added signing certificate reference according to the
     * (X/P/C)AdES specifications.
     */
    public static final String ADES_SIGNDATA = "ades.signdata";

    /**
     * Attribute containing the identifier of the AdES object if
     * present. This is use for XAdES signatures.
     */
    public static final String ADES_OBJECT_ID = "ades.object.id";

    /**
     * Attribute containing the generated AdES object. This is
     * used for XAdES signatures.
     */
    public static final String ADES_OBJECT_DATA = "ades.object.data";
}