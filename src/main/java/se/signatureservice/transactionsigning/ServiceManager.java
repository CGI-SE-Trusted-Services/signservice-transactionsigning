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

    private static SupportService sharedSupportServiceInstance;
    private static SignService sharedSignServiceInstance;
    private static ValidationService sharedValidationServiceInstance;

    /**
     * Get a shared instance of support service.
     *
     * @return Instance of default support service implementation.
     */
    public static SupportService getSupportService() {
        return getSupportService(null);
    }

    /**
     * Get a shared instance of support service, create if necessary based on given parameter
     *
     * @param serviceImplementation Classpath of support service implementation to use or null to use the default.
     * @return Instance of support service to use
     */
    public static SupportService getSupportService(String serviceImplementation) {
        if(sharedSupportServiceInstance == null) {
            String supportServiceImpl = serviceImplementation != null ? serviceImplementation : DEFAULT_SUPPORTSERVICE_IMPLEMENTATION;
            sharedSupportServiceInstance = newSupportService(supportServiceImpl);
        }
        return sharedSupportServiceInstance;
    }

    /**
     * Get a new SupportService instance, default implementation.
     *
     * @return Instance of default support service implementation.
     */
    public static SupportService newSupportService() {
        return newSupportService(DEFAULT_SUPPORTSERVICE_IMPLEMENTATION);
    }

    /**
     * Get a new SupportService instance, based on given parameter
     *
     * @param serviceImplementation Classpath of support service implementation to use.
     * @return Instance of support service to use
     */
    public static SupportService newSupportService(String serviceImplementation) {
        try {
            Class<?> c = ServiceManager.class.getClassLoader().loadClass(serviceImplementation);
            Object o = c.getDeclaredConstructor().newInstance();
            return (SupportService) o;
        } catch (Exception e) {
            log.error("Failed to create support service", e);
            return null;
        }
    }

    /**
     * Get a shared instance of sign service.
     *
     * @return Instance of default sign service implementation.
     */
    public static SignService getSignService() {
        return getSignService(null);
    }

    /**
     * Get a shared instance of sign service, create if necessary based on given parameter
     *
     * @param serviceImplementation Classpath of sign service implementation to use or null to use the default.
     * @return Instance of sign service to use
     */
    public static SignService getSignService(String serviceImplementation) {
        if(sharedSignServiceInstance == null) {
            String signServiceImpl = serviceImplementation != null ? serviceImplementation : DEFAULT_SIGNSERVICE_IMPLEMENTATION;
            sharedSignServiceInstance = newSignService(signServiceImpl);
        }
        return sharedSignServiceInstance;
    }

    /**
     * Get a new SignService instance, default implementation.
     *
     * @return Instance of default sign service implementation.
     */
    public static SignService newSignService() {
        return newSignService(DEFAULT_SIGNSERVICE_IMPLEMENTATION);
    }

    /**
     * Get a new SignService instance, based on given parameter
     *
     * @param serviceImplementation Classpath of sign service implementation to use.
     * @return Instance of sign service to use
     */
    private static SignService newSignService(String serviceImplementation) {
        try {
            Class<?> c = ServiceManager.class.getClassLoader().loadClass(serviceImplementation);
            Object o = c.getDeclaredConstructor().newInstance();
            return (SignService) o;
        } catch (Exception e) {
            log.error("Failed to create sign service", e);
            return null;
        }
    }

    /**
     * Get a shared instance of validation service.
     *
     * @return Instance of default validation service implementation.
     */
    public static ValidationService getValidationService() {
        return getValidationService(null);
    }

    /**
     * Get a shared instance of validation service, create if necessary based on given parameter
     *
     * @param serviceImplementation Classpath of validation service implementation to use or null to use the default.
     * @return Instance of validation service to use
     */
    public static ValidationService getValidationService(String serviceImplementation) {
        if(sharedValidationServiceInstance == null) {
            String validationServiceImpl = serviceImplementation != null ? serviceImplementation : DEFAULT_VALIDATIONSERVICE_IMPLEMENTATION;
            sharedValidationServiceInstance = newValidationService(validationServiceImpl);
        }
        return sharedValidationServiceInstance;
    }

    /**
     * Get a new ValidationService instance, default implementation.
     *
     * @return Instance of default validation service implementation.
     */
    public static ValidationService newValidationService() {
        return newValidationService(DEFAULT_VALIDATIONSERVICE_IMPLEMENTATION);
    }

    /**
     * Get a new ValidationService instance, based on given parameter
     *
     * @param serviceImplementation Classpath of validation service implementation to use.
     * @return Instance of validation service to use
     */
    public static ValidationService newValidationService(String serviceImplementation) {
        try {
            Class<?> c = ServiceManager.class.getClassLoader().loadClass(serviceImplementation);
            Object o = c.getDeclaredConstructor().newInstance();
            return (ValidationService) o;
        } catch (Exception e) {
            log.error("Failed to create validation service", e);
            return null;
        }
    }
}
