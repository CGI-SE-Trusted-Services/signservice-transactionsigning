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
package se.signatureservice.transactionsigning.common;

/**
 * Class that defines various mimetypes that are used in the system.
 *
 * @author Tobias Agerberg
 */
public class MimeType {
    /**
     * Extensible Markup Language (XML) file
     */
    public static final MimeType XML = new MimeType("text/xml");

    /**
     * Portable Document Format (PDF) file
     */
    public static final MimeType PDF = new MimeType("application/pdf");

    /**
     * Generic binary file
     */
    public static final MimeType BINARY = new MimeType("application/octet-stream");

    private String mimeType;
    private MimeType(String mimeType){
        this.mimeType = mimeType;
    }

    /**
     * Get mime type from a given path name.
     *
     * @param pathName Path name to get mimetype for
     * @return Mime type for given path name
     */
    public static MimeType getMimeType(String pathName) {
        String ext = "";

        int i = pathName.lastIndexOf('.');
        if (i > 0){
            ext = pathName.substring(i+1).toLowerCase();
        }

        switch(ext){
            case "xml":
                return XML;
            case "pdf":
                return PDF;
            default:
                return BINARY;
        }
    }

    /**
     * Get string representation of mime type.
     *
     * @return Mime type as a string.
     */
    @Override
    public String toString() {
        return mimeType;
    }

    @Override
    public boolean equals(Object o){
        if(o == this){
            return true;
        }

        if(o instanceof MimeType){
            if(((MimeType) o).mimeType.equals(mimeType)){
                return true;
            }
        }
        return false;
    }
}
