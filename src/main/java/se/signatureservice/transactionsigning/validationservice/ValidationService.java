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
package se.signatureservice.transactionsigning.validationservice;

import se.signatureservice.transactionsigning.ValidatorConfig;
import se.signatureservice.transactionsigning.common.*;

import java.util.List;

/**
 * Interface that describes a service to validate documents.
 *
 * @author Tobias Agerberg
 */
public interface ValidationService {

    /**
     * Initialize the validation service instance.
     *
     * @param config Configuration to use for the validation service instance.
     * @throws InvalidConfigurationException If an error occurred when initializing due to invalid configuration.
     */
    void init(ValidatorConfig config) throws InvalidConfigurationException;

    /**
     * Validate signed documents.
     *
     * @param documents List of documents to validate
     * @throws ValidationException If any of the documents contains an invalid signature.
     * @throws ValidationIOException If an intermittent I/O error occurred when validating the signature.
     * @throws InvalidParameterException If an error occurred due an invalid input parameters.
     */
    void validateDocuments(List<SignedDocument> documents) throws ValidationException, ValidationIOException, InvalidParameterException;
}
