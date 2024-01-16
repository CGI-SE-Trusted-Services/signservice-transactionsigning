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
package se.signatureservice.transactionsigning;

import java.security.KeyStore;

/**
 * Class containing transaction validator configuration.
 *
 * @author Tobias Agerberg
 */
public class ValidatorConfig {
    public final static String DEFAULT_VALIDATION_POLICY_NAME = "/validationpolicy.xml";
    public final static String DEFAULT_VALIDATION_TRUSTSTORE_TYPE = "JKS";
    public final static boolean DEFAULT_VALIDATION_STRICT = false;
    public final static boolean DEFAULT_VALIDATION_DISABLE_REVOCATIONCHECK = false;

    /**
     * Truststore containing trusted issuers to use when
     * verifying signed documents.
     */
    private KeyStore trustStore;

    /**
     * Validation policy to use.
     */
    private String policyName;

    /**
     * If strict validation should be performed.
     */
    private boolean strictValidation;

    /**
     * If revocation check should be disabled.
     */
    private boolean disableRevocation;

    public KeyStore getTrustStore() {
        return trustStore;
    }

    public void setTrustStore(KeyStore trustStore) {
        this.trustStore = trustStore;
    }

    public String getPolicyName() {
        return policyName;
    }

    public void setPolicyName(String policyName) {
        this.policyName = policyName;
    }

    public boolean isStrictValidation() {
        return strictValidation;
    }

    public void setStrictValidation(boolean strictValidation) {
        this.strictValidation = strictValidation;
    }

    public boolean isDisableRevocation() {
        return disableRevocation;
    }

    public void setDisableRevocation(boolean disableRevocation) {
        this.disableRevocation = disableRevocation;
    }
}
