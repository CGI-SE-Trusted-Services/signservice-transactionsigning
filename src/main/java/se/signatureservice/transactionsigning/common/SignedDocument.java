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
 * Class that describes a signed document to be processed in the system.
 *
 * @author Tobias Agerberg
 */
public class SignedDocument extends Document {
    /**
     * Create an empty document
     */
    public SignedDocument(){
    }

    /**
     * Create document from file system path
     *
     * @param pathName Path to document on file system
     */
    public SignedDocument(String pathName){
        super(pathName);
    }
}
