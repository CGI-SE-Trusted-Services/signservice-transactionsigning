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
 * Class that contains attributes used in SignRequestTask for
 * AdES (Advanced Electronic Signature) requests.
 *
 * @author Tobias Agerberg
 */
public class AdESSignRequestAttributes {

    /**
     * Type of AdES signature to perform.
     * @see AdESType
     */
    public static final String ADES_TYPE = "ades.type";

}