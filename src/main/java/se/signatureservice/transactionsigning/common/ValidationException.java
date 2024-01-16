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
package se.signatureservice.transactionsigning.common;

/**
 * Exception that indicates that the validation of a signature failed
 * and should not be trusted.
 *
 * @author Tobias Agerberg
 */
public class ValidationException extends Exception {

    /**
     * Exception that indicates that the validation of a signature failed
     * and should not be trusted.
     *
     * @param message description of the exception.
     */
    public ValidationException(String message){
        super(message);
    }

    /**
     * Exception that indicates that the validation of a signature failed
     * and should not be trusted.
     *
     * @param message description of the exception.
     * @param cause optional cause of the exception.
     */
    public ValidationException(String message, Throwable cause){
        super(message,cause);
    }

}
