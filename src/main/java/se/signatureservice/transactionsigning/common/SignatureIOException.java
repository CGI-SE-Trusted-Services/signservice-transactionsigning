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
package se.signatureservice.transactionsigning.common;

/**
 * Exception that indicates an intermittent error occurred while performing
 * a transaction signature (eg. network timeout).
 *
 * @author Tobias Agerberg
 */
public class SignatureIOException extends Exception {

    /**
     * Exception that indicates an intermittent error occurred while performing
     * a transaction signature (eg. network timeout).
     *
     * @param message description of the exception.
     */
    public SignatureIOException(String message){
        super(message);
    }

    /**
     * Exception that indicates an intermittent error occurred while performing
     * a transaction signature (eg. network timeout).
     *
     * @param message description of the exception.
     * @param cause optional cause of the exception.
     */
    public SignatureIOException(String message, Throwable cause){
        super(message,cause);
    }

}
