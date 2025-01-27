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

import org.json.JSONObject;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Class containing information about a pending transaction signature
 * that is not yet completed.
 *
 * @author Tobias Agerberg
 */
public class PendingSignature {
    private JSONObject signRequest;
    private Map<Integer, Document> documents;
    private Date signingDate;

    public PendingSignature(){
        documents = new HashMap<>();
    }

    public Map<Integer, Document> getDocuments() {
        return documents;
    }

    public void addDocument(Integer signTaskId, Document document){
        documents.put(signTaskId, document);
    }

    public JSONObject getSignRequest() {
        return signRequest;
    }

    public void setSignRequest(JSONObject signRequest) {
        this.signRequest = signRequest;
    }

    public Date getSigningDate(){
        return signingDate;
    }

    public void setSigningDate(Date signingDate){
        this.signingDate = signingDate;
    }
}
