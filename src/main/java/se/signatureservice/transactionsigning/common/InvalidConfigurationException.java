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
 * Exception that indicates an error occurred due to invalid
 * configuration.
 *
 * @author Tobias Agerberg
 */
public class InvalidConfigurationException extends Exception {

    /**
     * Exception that indicates an error occurred due to invalid
     * configuration.
     *
     * @param message description of the exception.
     */
    public InvalidConfigurationException(String message){
        super(message);
    }

    /**
     * Exception that indicates an error occurred due to invalid
     * configuration.
     *
     * @param message description of the exception.
     * @param cause optional cause of the exception.
     */
    public InvalidConfigurationException(String message, Throwable cause){
        super(message,cause);
    }

}
