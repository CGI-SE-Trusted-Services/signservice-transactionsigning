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

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Class that describes a document to be processed in the system.
 *
 * @author Tobias Agerberg
 */
public class Document {
    private String name;
    private MimeType mimeType;
    private byte[] content;

    /**
     * Create an empty document
     */
    public Document(){
    }

    /**
     * Create document from file system path
     *
     * @param pathName Path to document on file system
     */
    public Document(String pathName) {
        this(new File(pathName));
    }

    /**
     * Create document from File handle
     *
     * @param documentFile File handle
     */
    public Document(File documentFile) {
        this(documentFile.toPath());
    }

    /**
     * Create document from Path instance
     *
     * @param documentPath Path instance
     */
    public Document(Path documentPath){
        try {
            content = Files.readAllBytes(documentPath);
            name = documentPath.getFileName().toString();
            mimeType = MimeType.getMimeType(name);

        } catch(Exception e){
            throw new RuntimeException("Failed to create document", e);
        }
    }

    /**
     * Get name of document
     *
     * @return name of document
     */
    public String getName() {
        return name;
    }

    /**
     * Set the name of the document
     *
     * @param name Document name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get the document mime type
     *
     * @return Document mime type
     */
    public MimeType getMimeType() {
        return mimeType;
    }

    /**
     * Set the document mime type
     *
     * @param mimeType Document mime type
     */
    public void setMimeType(MimeType mimeType) {
        this.mimeType = mimeType;
    }

    /**
     * Get raw content of the document.
     *
     * @return Content of the document
     */
    public byte[] getContent() {
        return content;
    }

    /**
     * Set the content of the document
     *
     * @param content Raw document content
     */
    public void setContent(byte[] content) {
        this.content = content;
    }
}
