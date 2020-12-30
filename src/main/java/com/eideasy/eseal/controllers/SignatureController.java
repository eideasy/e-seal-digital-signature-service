package com.eideasy.eseal.controllers;

import com.eideasy.eseal.SignatureCreateException;
import com.eideasy.eseal.hsm.HsmSigner;
import com.eideasy.eseal.hsm.HsmSignerFactory;
import com.eideasy.eseal.models.*;
import org.apache.tomcat.util.buf.HexUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

@RestController
public class SignatureController {

    private static final Logger logger = LoggerFactory.getLogger(com.eideasy.eseal.controllers.SignatureController.class);

    @Autowired
    private Environment env;

    @Autowired
    HsmSignerFactory factory;

    @PostMapping("/api/get-certificate")
    public ResponseEntity<?> getCertificate(@RequestBody CertificateRequest request) {
        CertificateResponse response = new CertificateResponse();
        String certificate;
        try {
            verifyTimestamp(request);
            verifyCertificateMac(request);
            HsmSigner hmsSigner = factory.getSigner(request.getKeyId());
            certificate = hmsSigner.getCertificate(request.getKeyId());
            response.setCertificate(certificate);
        } catch (SignatureCreateException | Exception e) {
            logger.error("Getting certificate failed", e);
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            e.printStackTrace(pw);
            String sStackTrace = sw.toString();
            String errorMessage = e.getClass() + " " + e.getMessage() + " \n" + sStackTrace;
            response.setMessage(errorMessage);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/api/create-seal")
    public ResponseEntity<?> createSignature(@RequestBody SealRequest request) throws SignatureCreateException {
        logger.info("Signing digest " + request.getDigest());

        SealResponse response = new SealResponse();
        final String signAlgorithm = request.getAlgorithm(); // "SHA256withRSA" or SHA256withECDSA;

        String keyPass = env.getProperty("key_id." + request.getKeyId() + ".password");
        if (keyPass == null) {
            logger.error("Private key PIN/password not configured");
            response.setStatus("error");
            response.setMessage("Private key PIN/password not configured");
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }

        String base64Signature;
        try {
            verifySealMac(request);
            HsmSigner hmsSigner = factory.getSigner(request.getKeyId());
            long start = System.currentTimeMillis();
            byte[] signature = hmsSigner.signDigest(signAlgorithm, HexUtils.fromHexString(request.getDigest()), request.getKeyId());
            base64Signature = Base64.getEncoder().encodeToString(signature);
            long end = System.currentTimeMillis();
            logger.info("Signature done " + (end - start) + "ms. Value=" + base64Signature);
        } catch (SignatureCreateException | Exception e) {
            logger.error("E-seal creation failed", e);
            response.setStatus("error");
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            e.printStackTrace(pw);
            String sStackTrace = sw.toString();
            String errorMessage = e.getClass() + " " + e.getMessage() + " \n" + sStackTrace;
            response.setMessage(errorMessage);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }

        response.setSignature(base64Signature);
        response.setAlgorithm(signAlgorithm);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    protected boolean verifyCertificateMac(CertificateRequest request) throws NoSuchAlgorithmException, InvalidKeyException, SignatureCreateException {
        String message = "" + request.getKeyId() + request.getTimestamp() + "/api/get-certificate";
        return verifyMac(message, request.getHmac(), request.getKeyId());
    }

    protected boolean verifySealMac(SealRequest request) throws NoSuchAlgorithmException, InvalidKeyException, SignatureCreateException {
        String message = "" + request.getDigest() + request.getAlgorithm() + request.getKeyId() + request.getTimestamp() + "/api/create-seal";
        return verifyMac(message, request.getHmac(), request.getKeyId());
    }

    protected boolean verifyTimestamp(TimestampedRequest request) throws SignatureException {
        long currentTime = System.currentTimeMillis() / 1000;

        if (request.getTimestamp() > (currentTime + 60) || request.getTimestamp() < (currentTime - 60)) {
            String message = "Timestamp out of sync. request=" + request.getTimestamp() + " system=" + currentTime;
            logger.error(message);
            throw new SignatureException(message);
        }
        return true;
    }

    protected boolean verifyMac(String message, String hmac, String keyId) throws NoSuchAlgorithmException, InvalidKeyException, SignatureCreateException {
        // Properties must have this value configured.
        String hmacKey = env.getProperty("key_id." + keyId + ".hmac_key");
        if (hmacKey == null) {
            logger.error("Hmac key not configured");
            throw new SignatureCreateException("HMAC key not configured");
        }

        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(hmacKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        sha256_HMAC.init(secret_key);
        String calcHmac = HexUtils.toHexString(sha256_HMAC.doFinal(message.getBytes(StandardCharsets.UTF_8)));
        if (!calcHmac.equals(hmac)) {
            logger.error("Mac does not match");
            logger.info("Calculated mac: " + calcHmac + ", original is: " + hmac);
            logger.info("Message: " + message + " key=" + hmacKey.substring(0, 5));
            throw new SignatureCreateException("HMAC not matching");
        }

        return true;
    }
}
