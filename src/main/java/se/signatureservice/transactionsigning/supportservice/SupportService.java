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
package se.signatureservice.transactionsigning.supportservice;

import se.signatureservice.transactionsigning.SignerConfig;
import se.signatureservice.transactionsigning.common.*;

import java.util.List;

/**
 * Interface that describes a service to generate a remote signing request
 * that can be sent to a central remote signature server.
 *
 * @author Tobias Agerberg
 */
public interface SupportService {

    /**
     * Initialize the support service instance.
     *
     * @param config Configuration to use for the support service instance.
     * @throws InvalidConfigurationException If an error occurred when initializing due to invalid configuration.
     */
    void init(SignerConfig config) throws InvalidConfigurationException;

    /**
     * Generate a signature request in JSON format for a given list of documents
     * to be sent to remote signature server. Documents must be stored using a
     * unique request ID for generated request.
     *
     * @param documents List of documents to request signatures for.
     * @return Signature request in JSON format.
     * @throws SignatureException If an internal error occurred when generating the request.
     * @throws SignatureIOException If an intermittent I/O error occurred when generating the request.
     * @throws InvalidParameterException If an error occurred due to invalid document(s).
     */
    String generateSignRequest(List<Document> documents) throws SignatureException, SignatureIOException, InvalidParameterException;


    /**
     * Process a signature response in JSON format returned by remote signature
     * server. This method must be called with a response based on a request from
     * a previous call to generateSignRequest.
     *
     * @param response Response in JSON format to process
     * @return List of signed documents.
     * @throws SignatureException If an internal error occurred when generating the request.
     * @throws SignatureIOException If an intermittent I/O error occurred when generating the request.
     * @throws InvalidParameterException If an error occurred due an invalid response.
     */
    List<SignedDocument> processSignResponse(String response) throws SignatureException, SignatureIOException, InvalidParameterException;
}
