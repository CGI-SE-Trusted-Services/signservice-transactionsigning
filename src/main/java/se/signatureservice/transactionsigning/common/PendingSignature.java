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

import java.util.Date;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * Class containing information about a pending transaction signature
 * that is not yet completed.
 *
 * @author Tobias Agerberg
 */
public class PendingSignature {
    private final Map<Integer, Document> documents;
    private final Date signingDate;

    public PendingSignature(Date signingDate) {
        this.signingDate = signingDate;
        this.documents = new ConcurrentHashMap<>();
    }

    public Map<Integer, Document> getDocuments() {
        return documents;
    }

    public void addDocument(Integer signTaskId, Document document) {
        documents.put(signTaskId, document);
    }

    public Date getSigningDate() {
        return signingDate;
    }
}
