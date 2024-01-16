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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CommonUtils {

    /**
     * Creates X509Certificate from byte[].
     *
     * @param cert byte array containing certificate in DER-format
     * @return X509Certificate
     * @throws CertificateException If certificate could not be created from given byte array.
     */
    public static X509Certificate getCertfromByteArray(byte[] cert)
            throws CertificateException {
        try{
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate x509cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(cert));
            if(x509cert == null){
                throw new CertificateException("Error invalid certificate data");
            }
            return x509cert;
        } catch(Exception e){
            throw new CertificateException("Failed to create certificate: " + e.getMessage(), e);
        }
    }

    /**
     * Read all bytes from an inputstream and turn them in to a byte array
     * @param inputStream InputStream to read from
     * @return Byte array that contains all bytes read from the input stream.
     * @throws IOException If error occurred while reading from the stream.
     */
    public static byte[] getBytesFromInputStream(InputStream inputStream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int count;
        byte[] data = new byte[16384];

        while ((count = inputStream.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, count);
        }

        return buffer != null ? buffer.toByteArray() : null;
    }
}
