package com.eideasy.eseal.hsm.pkcs11;

import com.eideasy.eseal.SignatureCreateException;
import com.eideasy.eseal.hsm.HsmSigner;
import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.objects.ECDSAPrivateKey;
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

public class PKCS11Signer extends HsmSigner {

    private static final Logger logger = LoggerFactory.getLogger(PKCS11Signer.class);

    public String getCertificate(String keyId) throws SignatureCreateException {
        logger.info("Getting certificate for key " + keyId);
        byte[] encodedCert = null;
        Session session = null;
        try {
            session = getSession(keyId);
            session.findObjectsInit(new X509PublicKeyCertificate());
            Object[] objects = session.findObjects(1);

            if (objects.length > 0) {
                X509PublicKeyCertificate firstCertificate = ((X509PublicKeyCertificate) objects[0]);
                encodedCert = firstCertificate.getValue().getByteArrayValue();
            }

            for (Object object : objects) {
                if (object instanceof X509PublicKeyCertificate) {

                    break;
                }
            }
        } catch (IOException | TokenException e) {
            logger.error("Sertificate loading failed:" + e.getMessage(), e);
            throw new SignatureCreateException("Keystore loading failed", e);
        } finally {
            if (session != null) {
                try {
                    session.getModule().finalize();
                } catch (Throwable throwable) {
                    logger.error("Failed to finalize PKCS11 session");
                }
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

    public byte[] signDigest(String signAlgorithm, byte[] digest, String keyId) throws SignatureCreateException {
        logger.info("Creating signature in PKCS11 for key=" + keyId + ", algorithm=" + signAlgorithm);
        Session session = null;
        try {
            session = getSession(keyId);
            if (signAlgorithm.toLowerCase().contains("rsa")) {
                RSAPrivateKey templateSignatureKey = new RSAPrivateKey();
                templateSignatureKey.getSign().setBooleanValue(Boolean.TRUE);
                session.findObjectsInit(templateSignatureKey);
                Object[] foundSignatureKeyObjects = session.findObjects(10);

                RSAPrivateKey signatureKey = null;

                if (foundSignatureKeyObjects.length > 0) {
                    signatureKey = (RSAPrivateKey) foundSignatureKeyObjects[0];
                    logger.info("Signature key: " + signatureKey.getLabel());
                }

                session.findObjectsFinal();
                Mechanism signatureMechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS);

                session.signInit(signatureMechanism, signatureKey);
                return session.sign(wrapForRsaSign(digest, "SHA256"));
            } else {
                ECDSAPrivateKey templateSignatureKey = new ECDSAPrivateKey();
                templateSignatureKey.getSign().setBooleanValue(Boolean.TRUE);
                session.findObjectsInit(templateSignatureKey);
                Object[] foundSignatureKeyObjects = session.findObjects(1); // find first

                ECDSAPrivateKey signatureKey = null;
                if (foundSignatureKeyObjects.length > 0) {
                    signatureKey = (ECDSAPrivateKey) foundSignatureKeyObjects[0];
                    logger.info("Signature key: " + signatureKey.getLabel());
                }

                session.findObjectsFinal();
                Mechanism signatureMechanism = Mechanism.get(PKCS11Constants.CKM_ECDSA);

                session.signInit(signatureMechanism, signatureKey);
                return session.sign(digest);
            }

        } catch (Throwable e) {
            logger.error("Signature creation failed: " + e.getMessage(), e);
            throw new SignatureCreateException("Signature creation failed", e);
        } finally {
            if (session != null) {
                try {
                    session.getModule().finalize();
                } catch (Throwable throwable) {
                    logger.error("Failed to finalize PKCS11 session");
                }
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
                token = slot.getToken();
                String currentTokenLabel = token.getTokenInfo().getLabel().trim();
                if (currentTokenLabel.equals(tokenLabel)) {
                    logger.info("Found token with label " + token.getTokenInfo().getLabel());
                    break;
                }
            }

            if (token == null) {
                throw new SignatureCreateException("No tokens found with label=" + tokenLabel);
            }
            session = token.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RO_SESSION, null, null);

            String password = env.getProperty("key_id." + keyId + ".password");
            if (password == null) {
                logger.error("Property key_id." + keyId + ".password is empty");
                throw new SignatureCreateException("Property key_id." + keyId + ".password is empty");
            }

            session.login(Session.UserType.USER, password.toCharArray());

        } catch (PKCS11Exception e) {
            if (!e.getMessage().equals("CKR_CRYPTOKI_ALREADY_INITIALIZED") && !e.getMessage().equals("CKR_USER_ALREADY_LOGGED_IN")) {
                throw new SignatureCreateException("Cannot initialize PKCS11 module: " + e.getMessage(), e);
            }
        }

        return session;
    }

}
