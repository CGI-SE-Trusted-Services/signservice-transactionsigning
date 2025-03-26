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

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.signature.AbstractSignatureParameters;
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
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
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

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;


/**
 * Implementation of support service to be used locally.
 *
 * @author Tobias Agerberg
 */
public class DefaultSupportService implements SupportService {
    private static final Logger log = LoggerFactory.getLogger(DefaultSupportService.class);

    private final XAdESService xAdESService;
    private final PAdESService pAdESService;
    private final CAdESService cAdESService;

    private SignerConfig config;
    private volatile boolean initialized;

    private final Map<String, PendingSignature> pendingSignatures;

    public DefaultSupportService(){
        xAdESService = new XAdESService(new CommonCertificateVerifier());
        pAdESService = new PAdESService(new CommonCertificateVerifier());
        cAdESService = new CAdESService(new CommonCertificateVerifier());

        pendingSignatures = new ConcurrentHashMap<>();
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
        if (initialized) {
            throw new InvalidConfigurationException("Service is already initialized");
        }
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
     * @throws InvalidParameterException If an error occurred due to invalid document(s).
     */
    @Override
    public String generateSignRequest(List<Document> documents) throws SignatureException, InvalidParameterException {
        if(!initialized){
            throw new SignatureException("SupportService must be initialized before calling generateSignRequest");
        }

        JSONObject signRequest = new JSONObject();
        List<JSONObject> signRequestTasks = new ArrayList<>();

        PendingSignature pendingSignature = new PendingSignature(DateUtils.round(new Date(), Calendar.SECOND));
        String requestId = UUID.randomUUID().toString();

        for (int i = 0; i < documents.size(); i++) {
            Document document = documents.get(i);
            if (document == null) {
                throw new InvalidParameterException("Document at index " + i + " is null");
            }

            Integer signTaskId = i + 1;
            String adesType = AdESType.fromMimeType(document.getMimeType());

            JSONObject task = new JSONObject()
                    .put("signTaskId", String.valueOf(signTaskId))
                    .put("signType", config.getSignType())
                    .put("keyId", config.getKeyId())
                    .put("signRequestData", generateToBeSigned(document, pendingSignature.getSigningDate(), requestId))
                    .put("attributes", new JSONObject().put("ades.type", adesType));

            signRequestTasks.add(task);
            pendingSignature.addDocument(signTaskId, document);
        }

        signRequest.put("requestId", requestId)
                .put("signRequestTasks", signRequestTasks);

        pendingSignatures.putIfAbsent(requestId, pendingSignature);
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
        if(!initialized){
            throw new SignatureException("SupportService must be initialized before calling generateSignRequest");
        }

        JSONObject signResponse;
        String requestId;

        try {
            signResponse = new JSONObject(response);
            requestId = signResponse.getString("requestId");
        } catch(Exception e){
            throw new SignatureException("Failed to parse sign response: " + (e.getCause() != null ? e.getCause().getMessage() : e.getMessage()), e);
        }

        List<SignedDocument> signedDocuments = new ArrayList<>();
        try {
            PendingSignature pendingSignature = pendingSignatures.get(requestId);
            if(pendingSignature == null){
                log.error("No pending transaction found with requestId: {}", requestId);
                throw new SignatureException("No pending transaction found with requestId: " + requestId);
            }

            JSONArray signResponseTasks = signResponse.getJSONArray("signResponseTasks");
            Map<Integer, Document> pendingDocuments = pendingSignature.getDocuments();

            for (int i = 0; i < signResponseTasks.length(); i++) {
                JSONObject task = signResponseTasks.getJSONObject(i);
                Integer signTaskId = Integer.parseInt(task.getString("signTaskId"));
                Document document = pendingDocuments.get(signTaskId);

                byte[] adesSignData = SignTaskUtils.getBinaryResponseAttribute(signResponseTasks.getJSONObject(i), AdESSignResponseAttributes.ADES_SIGNDATA);
                byte[] adesObject = SignTaskUtils.getBinaryResponseAttribute(signResponseTasks.getJSONObject(i), AdESSignResponseAttributes.ADES_OBJECT_DATA);

                List<X509Certificate> x509SigningCertificates = parseSigningCertificates(task);
                if (x509SigningCertificates.isEmpty()) {
                    log.error("Signature response (requestId={}) did not contain any signature certificates (signTaskId={}).", requestId, signTaskId);
                    continue;
                }

                CertificateToken signatureToken = new CertificateToken(x509SigningCertificates.get(0));
                List<CertificateToken> signatureTokenChain = new ArrayList<>();
                for(X509Certificate certificate : x509SigningCertificates){
                    signatureTokenChain.add(new CertificateToken(certificate));
                }

                DSSDocument dssDocument = DSSUtils.createDSSDocument(document);
                AbstractSignatureParameters dssParameters = getSignatureParameters(document.getMimeType());
                dssParameters.bLevel().setSigningDate(pendingSignature.getSigningDate());
                var exactEncryptionAlgo = dssParameters.getEncryptionAlgorithm();
                dssParameters.setSigningCertificate(signatureToken);

                // BC RSA Public keys will report "algorithm", either "RSASSA-PSS" or "RSA"
                // In our specific case always "RSA", since we have not actively specified any algorithmIdentifier.
                // In case the signing algorithm is RSASSA-PSS (the default), we need to re-set it on the parameters object,
                // See comment from the eu lib on method AbstractSignatureParameters.setSigningCertificate
                if (signatureToken.getPublicKey().getAlgorithm().startsWith("RSA")) {
                    dssParameters.setEncryptionAlgorithm(exactEncryptionAlgo);
                }

                dssParameters.setCertificateChain(signatureTokenChain);

                if(adesSignData != null){
                    dssParameters.setSignedData(adesSignData);
                }

                SignatureValue signatureValue = new SignatureValue(SignatureAlgorithm.forJAVA(config.getSignatureAlgorithm()), Base64.decode(task.getString("signResponseData")));

                DSSDocument dssSignedDocument = signDocument(dssDocument, dssParameters, signatureValue, adesObject, requestId);
                if(dssSignedDocument != null) {
                    SignedDocument signedDocument = new SignedDocument();
                    signedDocument.setName(document.getName());
                    signedDocument.setMimeType(document.getMimeType());
                    signedDocument.setContent(CommonUtils.getBytesFromInputStream(dssSignedDocument.openStream()));
                    signedDocuments.add(signedDocument);
                } else {
                    log.error("Failed to create signed document for signTaskId={}", signTaskId);
                }
            }
        } catch(Exception e){
            throw new SignatureException("Failed to process sign response: " + (e.getCause() != null ? e.getCause().getMessage() : e.getMessage()), e);
        } finally {
            // Clear pending signature data when request has processed.
            pendingSignatures.remove(requestId);
        }
        return signedDocuments;
    }

    private DSSDocument signDocument(DSSDocument dssDocument, AbstractSignatureParameters dssParameters, SignatureValue signatureValue, byte[] adesObject, String requestId) throws SignatureException {
        try {
            if (dssDocument.getMimeType() == MimeTypeEnum.PDF) {
                PAdESSignatureParameters pAdESParameters = (PAdESSignatureParameters) dssParameters;
                pAdESParameters.setSignerName(requestId);
                return pAdESService.signDocument(dssDocument, pAdESParameters, signatureValue);
            } else if (dssDocument.getMimeType() == MimeTypeEnum.XML) {
                XAdESSignatureParameters xAdESParameters = (XAdESSignatureParameters) dssParameters;
                if (adesObject != null) {
                    xAdESParameters.setSignedAdESObject(adesObject);
                } else {
                    throw new SignatureException("Required AdES object not found in signature response");
                }
                return xAdESService.signDocument(dssDocument, xAdESParameters, signatureValue);
            } else if (dssDocument.getMimeType() == MimeTypeEnum.BINARY) {
                CAdESSignatureParameters cAdESParameters = (CAdESSignatureParameters) dssParameters;
                return cAdESService.signDocument(dssDocument, cAdESParameters, signatureValue);
            } else {
                throw new SignatureException("Unsupported MIME type: " + dssDocument.getMimeType());
            }
        } catch (Exception e) {
            throw new SignatureException("Failed to sign document: " + e.getMessage(), e);
        }
    }

    private List<X509Certificate> parseSigningCertificates(JSONObject task) throws CertificateException {
        List<X509Certificate> certificates = new ArrayList<>();
        JSONArray signingCertificates = task.getJSONArray("signingCertificates");
        for (int j = 0; j < signingCertificates.length(); j++) {
            String base64Cert = signingCertificates.getString(j);
            certificates.add(CommonUtils.getCertfromByteArray(Base64.decode(base64Cert.getBytes(StandardCharsets.UTF_8))));
        }
        return certificates;
    }

    private String generateToBeSigned(Document document, Date signingDate, String requestId) throws SignatureException {
        try {
            DSSDocument dssDocument = DSSUtils.createDSSDocument(document);
            AbstractSignatureParameters dssParameters = getSignatureParameters(document.getMimeType());
            dssParameters.setGenerateTBSWithoutCertificate(true);
            dssParameters.bLevel().setSigningDate(signingDate);

            byte[] dataToBeSigned;
            if (document.getMimeType() == MimeType.PDF) {
                PAdESSignatureParameters pAdESParameters = (PAdESSignatureParameters) dssParameters;
                log.debug("Preparing for PAdES signature");
                pAdESParameters.setSignerName(requestId);
                dataToBeSigned = pAdESService.getDataToSign(dssDocument, pAdESParameters).getBytes();
            } else if (document.getMimeType() == MimeType.XML) {
                XAdESSignatureParameters xAdESParameters = (XAdESSignatureParameters) dssParameters;
                log.debug("Preparing for XAdES signature");
                dataToBeSigned = xAdESService.getDataToSign(dssDocument, xAdESParameters).getBytes();
            } else if (document.getMimeType() == MimeType.BINARY) {
                CAdESSignatureParameters cAdESParameters = (CAdESSignatureParameters) dssParameters;
                dataToBeSigned = cAdESService.getDataToSign(dssDocument, cAdESParameters).getBytes();
            } else {
                throw new SignatureException("Unsupported MIME type: " + document.getMimeType());
            }

            return Base64.toBase64String(dataToBeSigned);
        } catch (Exception e) {
            throw new SignatureException("Failed to generate data to be signed: " + e.getMessage(), e);
        }
    }

    private AbstractSignatureParameters getSignatureParameters(MimeType mimeType) throws SignatureException {
        AbstractSignatureParameters parameters;

        if(mimeType == MimeType.PDF){
            PAdESSignatureParameters p = new PAdESSignatureParameters();
            p.setSignatureLevel(SignatureLevel.valueByName(config.getPadesSignatureLevel()));
            p.setSignaturePackaging(SignaturePackaging.valueOf(config.getPadesSignaturePacking()));
            parameters = p;
        } else if(mimeType == MimeType.XML){
            XAdESSignatureParameters p = new XAdESSignatureParameters();
            p.setSignatureLevel(SignatureLevel.valueByName(config.getXadesSignatureLevel()));
            p.setSignaturePackaging(SignaturePackaging.valueOf(config.getXadesSignaturePacking()));
            p.setSigningCertificateDigestMethod(SignatureAlgorithm.forJAVA(config.getSignatureAlgorithm()).getDigestAlgorithm());
            p.setSignedInfoCanonicalizationMethod(config.getXadesSignedPropertiesCanonicalizationMethod());
            p.setSignedPropertiesCanonicalizationMethod(config.getXadesSignedPropertiesCanonicalizationMethod());
            p.setXPathLocationString(config.getXadesXPathLocation());
            parameters = p;
        } else if(mimeType == MimeType.BINARY){
            CAdESSignatureParameters p = new CAdESSignatureParameters();
            p.setSignatureLevel(SignatureLevel.valueByName(config.getCadesSignatureLevel()));
            p.setSignaturePackaging(SignaturePackaging.valueOf(config.getCadesSignaturePacking()));
            parameters = p;
        } else {
            throw new SignatureException("Unsupported mimetype: " + mimeType.toString());
        }

        parameters.setEncryptionAlgorithm(SignatureAlgorithm.forJAVA(config.getSignatureAlgorithm()).getEncryptionAlgorithm());
        parameters.setDigestAlgorithm(SignatureAlgorithm.forJAVA(config.getSignatureAlgorithm()).getDigestAlgorithm());

        return parameters;
    }
}
