package com.eideasy.eseal.hsm.pkcs11;

import com.eideasy.eseal.SignatureCreateException;
import com.eideasy.eseal.hsm.HsmSigner;
import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.objects.ECPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import org.bouncycastle.asn1.*;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class PKCS11Signer extends HsmSigner {

    private static final Logger logger = LoggerFactory.getLogger(PKCS11Signer.class);
    private static Map<String, Session> sessions = new HashMap<>();

    public String getCertificate(String keyId) throws SignatureCreateException {
        byte[] encodedCert = null;
        Session session = null;
        try {
            String objectId = env.getProperty("key_id." + keyId + ".object-id");

            logger.info("Getting certificate for key " + keyId + " with configured ID: " + objectId);

            session = getSession(keyId);
            session.findObjectsInit(new X509PublicKeyCertificate());
            Object[] objects = session.findObjects(100);

            for (Object object : objects) {
                X509PublicKeyCertificate certificate = ((X509PublicKeyCertificate) object);
                if (certificate.getId().toString().equals(objectId)) {
                    logger.info("Found certificate: " + certificate.getId());
                    encodedCert = certificate.getValue().getByteArrayValue();
                    break;
                } else {
                    logger.info("Certificate not found for ID: " + certificate.getId());
                }
            }
        } catch (IOException | TokenException e) {
            if ("CKR_DEVICE_REMOVED".equals(e.getMessage())) {
                logger.info(e.getMessage() + ", reopening session");
                sessions.remove(keyId);
                session = null;
                return getCertificate(keyId);
            }
            if (e.getMessage() != null && e.getMessage().contains("CKR_SESSION_HANDLE_INVALID")) {
                logger.info("CKR_SESSION_HANDLE_INVALID, restarting");
                sessions.remove(keyId);
                session = null;
                return getCertificate(keyId);
            }
            logger.error("Certificate loading failed:" + e.getMessage(), e);
            throw new SignatureCreateException("Keystore loading failed", e);
        } finally {
            try {
                if (session != null) {
                    session.findObjectsFinal();
                }
            } catch (TokenException e) {
                logger.info("Cannot finalize finding object", e);
            }
        }

        if (encodedCert != null) {
            return Base64.getEncoder().encodeToString(encodedCert);
        } else {
            logger.error("Certificate not found for key " + keyId);
            throw new SignatureCreateException("Certificate not found for key " + keyId);
        }
    }

    protected byte[] wrapForRsaSign(byte[] dig, String hashAlgo) throws SignatureException {
        ASN1ObjectIdentifier oid = new DefaultDigestAlgorithmIdentifierFinder().find(hashAlgo).getAlgorithm();
        ASN1Sequence oidSeq = new DERSequence(new ASN1Encodable[]{oid, DERNull.INSTANCE});
        ASN1Sequence seq = new DERSequence(new ASN1Encodable[]{oidSeq, new DEROctetString(dig)});
        try {
            return seq.getEncoded();
        } catch (IOException e) {
            throw new SignatureException("Cannot convert RSA digest to ASN.1 structure");
        }
    }

    public byte[] signDigest(String signAlgorithm, byte[] digest, String keyId, char[] password) throws SignatureCreateException {
        logger.info("Creating signature in PKCS11 for key=" + keyId + ", algorithm=" + signAlgorithm);
        Session session = null;
        try {
            session = getSession(keyId);
            loginToToken(session, password);
            String objectId = env.getProperty("key_id." + keyId + ".object-id");

            if (signAlgorithm.toLowerCase().contains("rsa")) {
                logger.info("Signing with RSA key");
                RSAPrivateKey templateSignatureKey = new RSAPrivateKey();
                templateSignatureKey.getSign().setBooleanValue(Boolean.TRUE);
                session.findObjectsInit(templateSignatureKey);
                Object[] foundSignatureKeyObjects = session.findObjects(100);

                RSAPrivateKey signatureKey = null;

                for (Object sigKeyObject : foundSignatureKeyObjects) {
                    RSAPrivateKey nextKey = (RSAPrivateKey) sigKeyObject;
                    if (nextKey.getId().toString().equals(objectId)) {
                        logger.info("Signature key: " + nextKey.getLabel());
                        signatureKey = nextKey;
                        break;
                    }
                }

                if (signatureKey == null) {
                    throw new SignatureCreateException("Wrong PIN or signature key not found for ID: " + objectId);
                }

                Mechanism signatureMechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS);

                session.signInit(signatureMechanism, signatureKey);
                return session.sign(wrapForRsaSign(digest, "SHA256"));
            } else {
                logger.info("Signing with EC key");
                ECPrivateKey templateSignatureKey = new ECPrivateKey();
                templateSignatureKey.getSign().setBooleanValue(Boolean.TRUE);
                session.findObjectsInit(templateSignatureKey);
                Object[] foundSignatureKeyObjects = session.findObjects(100);

                ECPrivateKey signatureKey = null;
                for (Object sigKeyObject : foundSignatureKeyObjects) {
                    ECPrivateKey nextKey = (ECPrivateKey) sigKeyObject;
                    if (nextKey.getId().toString().equals(objectId)) {
                        logger.info("Signature key: " + nextKey.getLabel());
                        signatureKey = nextKey;
                        break;
                    }
                }

                if (signatureKey == null) {
                    throw new SignatureCreateException("Wrong PIN or signature key not found for ID: " + objectId);
                }

                Mechanism signatureMechanism = Mechanism.get(PKCS11Constants.CKM_ECDSA);

                session.signInit(signatureMechanism, signatureKey);
                return session.sign(digest);
            }

        } catch (Throwable e) {
            if ("CKR_DEVICE_REMOVED".equals(e.getMessage())) {
                logger.info(e.getMessage() + ", reopening session");
                sessions.remove(keyId);
                session = null;
                return signDigest(signAlgorithm, digest, keyId, password);
            }
            if ("CKR_SESSION_HANDLE_INVALID".equals(e.getMessage())) {
                logger.info("CKR_SESSION_HANDLE_INVALID, restarting");
                sessions.remove(keyId);
                session = null;
                return signDigest(signAlgorithm, digest, keyId, password);
            }
            logger.error("Signature creation failed: " + e.getClass() + ", " + e.getMessage(), e);
            throw new SignatureCreateException(e.getClass() + ", " + e.getMessage(), e);
        } finally {
            try {
                if (session != null) {
                    session.findObjectsFinal();
                }
            } catch (TokenException e) {
                logger.info("Cannot finalize finding object", e);
            }
        }
    }

    protected Session getSession(String keyId) throws IOException, TokenException, SignatureCreateException {
        String modulePath = env.getProperty("key_id." + keyId + ".pkcs11-path");
        if (modulePath == null) {
            logger.error("Property key_id." + keyId + ".pkcs11-path is empty");
            throw new SignatureCreateException("Property key_id." + keyId + ".pkcs11-path is empty");
        }
        String tokenLabel = env.getProperty("key_id." + keyId + ".token-label");
        if (tokenLabel == null) {
            logger.error("Property key_id." + keyId + ".token-label is empty");
            throw new SignatureCreateException("Property key_id." + keyId + ".token-label is empty");
        }
        Module pkcs11Module = Module.getInstance(modulePath);

        Session session = null;
        try {
            pkcs11Module.initialize(null);

            Slot[] slots = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
            Token token = null;
            for (Slot slot : slots) {
                String slotString = env.getProperty("key_id." + keyId + ".slot");
                if (slotString != null) {
                    Long slotId = Long.decode(slotString);
                    if (slot.getSlotID() != slotId) {
                        logger.info("Looking slot " + slotId + " found " + slot.getSlotID());
                        continue;
                    }
                }

                String currentTokenLabel = slot.getToken().getTokenInfo().getLabel().trim();
                logger.info("Checking token with label: " + currentTokenLabel);
                if (currentTokenLabel.equals(tokenLabel)) {
                    token = slot.getToken();
                    logger.info("Found token with label " + token.getTokenInfo().getLabel());
                    break;
                }
            }

            if (token == null) {
                throw new SignatureCreateException("No tokens found with label=" + tokenLabel);
            }

            session = sessions.get(keyId);
            if (session == null) {
                session = token.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RO_SESSION, null, null);
                sessions.put(keyId, session);
            }
        } catch (PKCS11Exception e) {
            if (!e.getMessage().equals("CKR_CRYPTOKI_ALREADY_INITIALIZED") && !e.getMessage().equals("CKR_USER_ALREADY_LOGGED_IN")) {
                throw new SignatureCreateException("Cannot initialize PKCS11 module: " + e.getMessage(), e);
            }
        }

        return session;
    }

    protected Session loginToToken(Session session, char[] password) throws SignatureCreateException {
        try {
            session.login(Session.UserType.USER, password);
        } catch (TokenException e) {
            logger.info("User already logged in. Logging out and in again.");
            if (e.getMessage().equals("CKR_USER_ALREADY_LOGGED_IN")) {
                try {
                    session.logout();
                    session.login(Session.UserType.USER, password);
                } catch (TokenException e2) {
                    throw new SignatureCreateException("Cannot initialize PKCS11 module: " + e2.getMessage(), e2);
                }
            }
        }

        logger.info("Logged in to token");
        return session;
    }

}
