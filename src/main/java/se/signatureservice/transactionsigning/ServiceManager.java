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
package se.signatureservice.transactionsigning;

import se.signatureservice.transactionsigning.signservice.SignService;
import se.signatureservice.transactionsigning.supportservice.SupportService;
import se.signatureservice.transactionsigning.validationservice.ValidationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service manager class used to dynamically create instances
 * of services.
 *
 * @author Tobias Agerberg
 */
public class ServiceManager {
    private final static Logger log = LoggerFactory.getLogger(ServiceManager.class);

    private final static String DEFAULT_SIGNSERVICE_IMPLEMENTATION = "se.signatureservice.transactionsigning.signservice.DefaultSignService";
    private final static String DEFAULT_SUPPORTSERVICE_IMPLEMENTATION = "se.signatureservice.transactionsigning.supportservice.DefaultSupportService";
    private final static String DEFAULT_VALIDATIONSERVICE_IMPLEMENTATION = "se.signatureservice.transactionsigning.validationservice.DefaultValidationService";

    private static SupportService supportService;
    private static SignService signService;
    private static ValidationService validationService;

    /**
     * Get default support service implementation.
     *
     * @return Instance of default support service implementation.
     */
    public static SupportService getSupportService() {
        return getSupportService(null);
    }

    /**
     * Get instance of support service based on given parameter
     *
     * @param serviceImplementation Classpath of support service implementation to use or null to use the default.
     * @return Instance of support service to use
     */
    public static SupportService getSupportService(String serviceImplementation) {
        if(supportService == null) {
            String supportServiceImpl = serviceImplementation != null ? serviceImplementation : DEFAULT_SUPPORTSERVICE_IMPLEMENTATION;
            try {
                Class<?> c = ServiceManager.class.getClassLoader().loadClass(supportServiceImpl);
                Object o = c.newInstance();
                supportService = (SupportService)o;
            } catch (Exception e) {
                log.error("Failed to create support service", e);
            }
        }
        return supportService;
    }

    /**
     * Get default support sign service implementation.
     *
     * @return Instance of default support service implementation.
     */
    public static SignService getSignService() {
        return getSignService(null);
    }

    /**
     * Get instance of sign service based on application
     * configuration.
     *
     * @param serviceImplementation Classpath of sign service implementation to use or null to use the default.
     * @return Instance of sign service to use
     */
    public static SignService getSignService(String serviceImplementation) {
        if(signService == null) {
            String signServiceImpl = serviceImplementation != null ? serviceImplementation : DEFAULT_SIGNSERVICE_IMPLEMENTATION;
            try {
                Class<?> c = ServiceManager.class.getClassLoader().loadClass(signServiceImpl);
                Object o = c.newInstance();
                signService = (SignService)o;
            } catch (Exception e) {
                log.error("Failed to create sign service", e);
            }
        }
        return signService;
    }

    /**
     * Get default validation service implementation.
     *
     * @return Instance of default validation service implementation.
     */
    public static ValidationService getValidationService() {
        return getValidationService(null);
    }

    /**
     * Get instance of validation service based on application
     * configuration.
     *
     * @param serviceImplementation Classpath of validation service implementation to use or null to use the default.
     * @return Instance of sign service to use
     */
    public static ValidationService getValidationService(String serviceImplementation) {
        if(validationService == null) {
            String validationServiceImpl = serviceImplementation != null ? serviceImplementation : DEFAULT_VALIDATIONSERVICE_IMPLEMENTATION;
            try {
                Class<?> c = ServiceManager.class.getClassLoader().loadClass(validationServiceImpl);
                Object o = c.newInstance();
                validationService = (ValidationService)o;
            } catch (Exception e) {
                log.error("Failed to create validation service", e);
            }
        }
        return validationService;
    }
}
