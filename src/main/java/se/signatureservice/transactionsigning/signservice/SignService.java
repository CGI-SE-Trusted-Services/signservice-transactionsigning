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
package se.signatureservice.transactionsigning.signservice;

import se.signatureservice.transactionsigning.SignerConfig;
import se.signatureservice.transactionsigning.common.InvalidConfigurationException;
import se.signatureservice.transactionsigning.common.InvalidParameterException;
import se.signatureservice.transactionsigning.common.SignatureException;
import se.signatureservice.transactionsigning.common.SignatureIOException;

/**
 * Interface that describes a service to handle signature requests and
 * produce a signature response.
 *
 * @author Tobias Agerberg
 */
public interface SignService {

    /**
     * Initialize the support service instance.
     *
     * @param config Configuration to use for the support service instance.
     * @throws InvalidConfigurationException If an error occurred when initializing due to invalid configuration
     */
    void init(SignerConfig config) throws InvalidConfigurationException;

    /**
     * Send signature request to obtain a signature response.
     *
     * @param signRequest Signature request in JSON format.
     * @return Signature response in JSON format.
     * @throws SignatureException If an internal error occurred during signature request.
     * @throws SignatureIOException If an intermittent I/O error occurred during signature request.
     * @throws InvalidParameterException If an error occurred due to an invalid signature request.
     */
    String requestSignature(String signRequest) throws SignatureException, SignatureIOException, InvalidParameterException;
}
