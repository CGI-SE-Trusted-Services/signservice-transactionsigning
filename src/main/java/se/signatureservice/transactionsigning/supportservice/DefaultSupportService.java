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
package se.signatureservice.transactionsigning.supportservice;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.apache.commons.lang3.time.DateUtils;
import se.signatureservice.transactionsigning.SignerConfig;
import se.signatureservice.transactionsigning.ades.AdESSignResponseAttributes;
import se.signatureservice.transactionsigning.ades.AdESType;
import se.signatureservice.transactionsigning.common.*;
import se.signatureservice.transactionsigning.util.CommonUtils;
import se.signatureservice.transactionsigning.util.DSSUtils;
import se.signatureservice.transactionsigning.util.SignTaskUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.bouncycastle.util.encoders.Base64;
import java.security.cert.X509Certificate;
import java.util.*;


/**
 * Implementation of support service to be used locally.
 *
 * @author Tobias Agerberg
 */
public class DefaultSupportService implements SupportService {
    private static final Logger log = LoggerFactory.getLogger(DefaultSupportService.class);

    private XAdESService xAdESService;
    private PAdESService pAdESService;
    private CAdESService cAdESService;

    private SignerConfig config;
    private boolean initialized;

    private Map<String, PendingSignature> pendingSignatures;

    public DefaultSupportService(){
        xAdESService = new XAdESService(new CommonCertificateVerifier());
        pAdESService = new PAdESService(new CommonCertificateVerifier());
        cAdESService = new CAdESService(new CommonCertificateVerifier());

        pendingSignatures = new HashMap<>();
        initialized = false;
    }

    /**
     * Initialize the support service instance.
     *
     * @param config Configuration to use for the support service instance.
     * @throws InvalidConfigurationException If an error occurred when initializing the service due to invalid configuration.
     */
    @Override
    public void init(SignerConfig config) throws InvalidConfigurationException {
        this.config = config;
        initialized = true;
    }

    /**
     * Generate a signature request in JSON format for a given list of documents
     * to be sent to remote signature server. Documents must be stored using a
     * unique request ID for generated request.
     *
     * @param documents List of documents to request signatures for.
     * @return Signature request in JSON format.
     * @throws SignatureException If an internal error occurred when generating the request.
     * @throws SignatureIOException If an intermittent I/O error occurred when generating the request.
     * @throws InvalidParameterException If an error occurred due to invalid document(s).
     */
    @Override
    public String generateSignRequest(List<Document> documents) throws SignatureException, SignatureIOException, InvalidParameterException {
        JSONObject signRequest = new JSONObject();
        List<JSONObject> signRequestTasks = new ArrayList<>();

        if(!initialized){
            throw new SignatureException("SupportService must be initialized before calling generateSignRequest");
        }

        PendingSignature pendingSignature = new PendingSignature();
        pendingSignature.setSigningDate(DateUtils.round(new Date(), Calendar.SECOND));
        String requestId = generateRequestId();

        for(int i=0;i<documents.size();i++){
            Integer signTaskId = (i+1);
            String adesType = AdESType.fromMimeType(documents.get(i).getMimeType());
            signRequestTasks.add(new JSONObject()
                    .put("signTaskId", String.valueOf(signTaskId))
                    .put("signType", config.getSignType())
                    .put("keyId", config.getKeyId())
                    .put("signRequestData", generateToBeSigned(documents.get(i), pendingSignature.getSigningDate(), requestId))
                    .put("attributes", new JSONObject()
                    .put("ades.type", adesType)));

            pendingSignature.addDocument(signTaskId, documents.get(i));
        }

        signRequest.put("requestId", requestId)
                .put("signRequestTasks", signRequestTasks);

        pendingSignature.setSignRequest(signRequest);
        pendingSignatures.put(requestId, pendingSignature);
        return signRequest.toString();
    }

    /**
     * Process a signature response in JSON format returned by remote signature
     * server. This method must be called with a response based on a request from
     * a previous call to generateSignRequest.
     *
     * @param response Response in JSON format to process
     * @return List of signed documents.
     * @throws SignatureException If an internal error occurred when generating the request.
     */
    @Override
    public List<SignedDocument> processSignResponse(String response) throws SignatureException {
        List<SignedDocument> signedDocuments = new ArrayList<>();

        if(!initialized){
            throw new SignatureException("SupportService must be initialized before calling generateSignRequest");
        }

        try {
            JSONObject signResponse = new JSONObject(response);
            String requestId = signResponse.getString("requestId");
            if(!pendingSignatures.containsKey(requestId)){
                throw new SignatureException("No pending transaction found with requestId: " + requestId);
            }

            PendingSignature pendingSignature = pendingSignatures.get(requestId);
            JSONArray signResponseTasks = signResponse.getJSONArray("signResponseTasks");

            Map<Integer, Document> pendingDocuments = pendingSignature.getDocuments();
            for(int i=0;i<signResponseTasks.length();i++){
                String signResponseData = signResponseTasks.getJSONObject(i).getString("signResponseData");
                Integer signTaskId = Integer.parseInt(signResponseTasks.getJSONObject(i).getString("signTaskId"));
                Document document = pendingDocuments.get(signTaskId);

                byte[] adesSignData = SignTaskUtils.getBinaryResponseAttribute(signResponseTasks.getJSONObject(i), AdESSignResponseAttributes.ADES_SIGNDATA);
                byte[] adesObject = SignTaskUtils.getBinaryResponseAttribute(signResponseTasks.getJSONObject(i), AdESSignResponseAttributes.ADES_OBJECT_DATA);

                List<X509Certificate> x509SigningCertificates = new ArrayList<>();
                JSONArray signingCertificates = signResponseTasks.getJSONObject(i).getJSONArray("signingCertificates");
                for(int j=0;j<signingCertificates.length();j++){
                    String base64cert = signingCertificates.getString(j);
                    x509SigningCertificates.add(CommonUtils.getCertfromByteArray(Base64.decode(base64cert.getBytes("UTF-8"))));
                }

                if(signingCertificates.isEmpty()){
                    log.error("Signature response (requestId=" + requestId + ") did not contain any signature certificates (signTaskId=" + signTaskId + ").");
                    continue;
                }

                CertificateToken signatureToken = new CertificateToken(x509SigningCertificates.get(0));
                List<CertificateToken> signatureTokenChain = new ArrayList<CertificateToken>();
                for(X509Certificate certificate : x509SigningCertificates){
                    signatureTokenChain.add(new CertificateToken(certificate));
                }

                DSSDocument dssDocument = DSSUtils.createDSSDocument(document);
                AbstractSignatureParameters dssParameters = getSignatureParameters(document.getMimeType());
                dssParameters.bLevel().setSigningDate(pendingSignature.getSigningDate());
                dssParameters.setSigningCertificate(signatureToken);
                dssParameters.setCertificateChain(signatureTokenChain);

                if(adesSignData != null){
                    dssParameters.setSignedData(adesSignData);
                }

                SignatureValue signatureValue = new SignatureValue(SignatureAlgorithm.forJAVA("SHA256withRSA"), Base64.decode(signResponseData));

                DSSDocument dssSignedDocument = null;
                if(document.getMimeType() == MimeType.PDF){
                    PAdESSignatureParameters pAdESParameters = (PAdESSignatureParameters)dssParameters;
                    pAdESParameters.setSignerName(requestId);
                    dssSignedDocument = pAdESService.signDocument(dssDocument, pAdESParameters, signatureValue);
                } else if(document.getMimeType() == MimeType.XML){
                    XAdESSignatureParameters xAdESSignatureParameters = (XAdESSignatureParameters)dssParameters;
                    if(adesObject != null){
                        xAdESSignatureParameters.setSignedAdESObject(adesObject);
                    } else {
                        throw new SignatureException("Required AdES object not found in signature response");
                    }

                    dssSignedDocument = xAdESService.signDocument(dssDocument, xAdESSignatureParameters, signatureValue);
                } else if(document.getMimeType() == MimeType.BINARY){
                    CAdESSignatureParameters cAdESSignatureParameters = (CAdESSignatureParameters)dssParameters;
                    dssSignedDocument = cAdESService.signDocument(dssDocument, cAdESSignatureParameters, signatureValue);
                }

                SignedDocument signedDocument = new SignedDocument();
                signedDocument.setName(document.getName());
                signedDocument.setMimeType(document.getMimeType());
                signedDocument.setContent(CommonUtils.getBytesFromInputStream(dssSignedDocument.openStream()));
                signedDocuments.add(signedDocument);
            }

            // Clear pending signature data when request has processed.
            pendingSignatures.remove(requestId);
        } catch(Exception e){
            throw new SignatureException("Failed to process sign response: " + (e.getCause() != null ? e.getCause().getMessage() : e.getMessage()), e);
        }
        return signedDocuments;
    }

    private String generateToBeSigned(Document document, Date signingDate, String requestId) throws SignatureException {
        byte[] dataToBeSigned = null;
        DSSDocument dssDocument = DSSUtils.createDSSDocument(document);

        AbstractSignatureParameters dssParameters = getSignatureParameters(document.getMimeType());
        dssParameters.setGenerateTBSWithoutCertificate(true);
        dssParameters.bLevel().setSigningDate(signingDate);

        if(document.getMimeType() == MimeType.PDF){
            PAdESSignatureParameters pAdESParameters = (PAdESSignatureParameters)dssParameters;
            log.debug("Preparing for PAdES signature");
            pAdESParameters.setSignerName(requestId);
            dataToBeSigned = pAdESService.getDataToSign(dssDocument, pAdESParameters).getBytes();
        } else if(document.getMimeType() == MimeType.XML){
            log.debug("Preparing for XAdES signature");
            XAdESSignatureParameters xAdESSignatureParameters = (XAdESSignatureParameters)dssParameters;
            dataToBeSigned = xAdESService.getDataToSign(dssDocument, xAdESSignatureParameters).getBytes();
        } else if(document.getMimeType() == MimeType.BINARY){
            log.debug("Preparing for CAdES signature");
            CAdESSignatureParameters cAdESSignatureParameters = (CAdESSignatureParameters)dssParameters;
            dataToBeSigned = cAdESService.getDataToSign(dssDocument, cAdESSignatureParameters).getBytes();
        }

        log.debug("Generated dataToBeSigned = " + (dataToBeSigned != null ? Base64.toBase64String(dataToBeSigned) : null));
        return dataToBeSigned != null ? Base64.toBase64String(dataToBeSigned) : null;
    }

    private AbstractSignatureParameters getSignatureParameters(MimeType mimeType) throws SignatureException {
        AbstractSignatureParameters parameters;

        if(mimeType == MimeType.PDF){
            PAdESSignatureParameters p = new PAdESSignatureParameters();
            p.setSignatureLevel(SignatureLevel.valueByName("PAdES-BASELINE-B"));
            p.setSignaturePackaging(SignaturePackaging.valueOf("ENVELOPED"));
            parameters = p;
        } else if(mimeType == MimeType.XML){
            XAdESSignatureParameters p = new XAdESSignatureParameters();
            p.setSignatureLevel(SignatureLevel.valueByName("XAdES-BASELINE-B"));
            p.setSignaturePackaging(SignaturePackaging.valueOf("ENVELOPED"));
            p.setSigningCertificateDigestMethod(SignatureAlgorithm.forJAVA("SHA256withRSA").getDigestAlgorithm());
            p.setSignedInfoCanonicalizationMethod("http://www.w3.org/2001/10/xml-exc-c14n#");
            p.setSignedPropertiesCanonicalizationMethod("http://www.w3.org/2001/10/xml-exc-c14n#");
            p.setXPathLocationString("node()[not(self::Signature)]");
            parameters = p;
        } else if(mimeType == MimeType.BINARY){
            CAdESSignatureParameters p = new CAdESSignatureParameters();
            p.setSignatureLevel(SignatureLevel.valueByName("CAdES-BASELINE-B"));
            p.setSignaturePackaging(SignaturePackaging.valueOf("ENVELOPING"));
            parameters = p;
        } else {
            throw new SignatureException("Unsupported mimetype: " + mimeType.toString());
        }

        parameters.setEncryptionAlgorithm(SignatureAlgorithm.forJAVA("SHA256withRSA").getEncryptionAlgorithm());
        parameters.setDigestAlgorithm(SignatureAlgorithm.forJAVA("SHA256withRSA").getDigestAlgorithm());

        return parameters;
    }

    /**
     * Generate unique request ID to be used in sign request.
     * @return Unique request ID
     */
    private String generateRequestId(){
        return UUID.randomUUID().toString();
    }
}
