/************************************************************************
 *                                                                       *
 *  Certificate Service - Remote Sign                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.transactionsigning.util;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import se.signatureservice.transactionsigning.common.Document;

public class DSSUtils {

    /**
     * Create DSSDocument from a given AbstractDocument
     * @param document AbstractDocument to create DSSDocument from
     * @return DSSDocument based on given AbstractDocument
     */
    public static DSSDocument createDSSDocument(Document document) {
        InMemoryDocument dssDocument = new InMemoryDocument();
        dssDocument.setName(document.getName());
        dssDocument.setBytes(document.getContent());
        dssDocument.setMimeType(MimeType.fromMimeTypeString(document.getMimeType().toString()));
        return dssDocument;
    }
}
