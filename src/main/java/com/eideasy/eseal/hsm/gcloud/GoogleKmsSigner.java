package com.eideasy.eseal.hsm.gcloud;

import com.eideasy.eseal.SignatureCreateException;
import com.eideasy.eseal.hsm.HsmSigner;
import com.google.cloud.kms.v1.*;
import com.google.protobuf.ByteString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;

public class GoogleKmsSigner extends HsmSigner {

    private static final Logger logger = LoggerFactory.getLogger(GoogleKmsSigner.class);

    private Environment env;

    public void setEnv(Environment env) {
        this.env = env;
    }

    @Override
    public String getCertificate(String keyId) throws KeyStoreException, CertificateEncodingException {
        return null;
    }

    @Override
    public byte[] signDigest(String algorithm, byte[] digest, String keyId, char[] keyPass) throws SignatureCreateException {
        // TODO untested!

        String prop = "key_id." + keyId + ".";
        String projectId = env.getProperty(prop + "projectId");
        String locationId = env.getProperty(prop + "locationId");
        String keyRingId = env.getProperty(prop + "keyRingId");
        String googleKeyId = env.getProperty(prop + "keyId");
        String keyVersionId = env.getProperty(prop + "keyVersionId");

        // Initialize client that will be used to send requests. This client only
        // needs to be created once, and can be reused for multiple requests. After
        // completing all of your requests, call the "close" method on the client to
        // safely clean up any remaining background resources.
        try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {
            // Build the key version name from the project, location, key ring, key,
            // and key version.
            CryptoKeyVersionName keyVersionName = CryptoKeyVersionName.of(projectId, locationId, keyRingId, googleKeyId, keyVersionId);

            // Build the digest object.
            Digest googleDigest = Digest.newBuilder().setSha256(ByteString.copyFrom(digest)).build();

            // Sign the digest.
            AsymmetricSignResponse result = client.asymmetricSign(keyVersionName, googleDigest);

            // Get the signature.
            return result.getSignature().toByteArray();
        } catch (IOException e) {
            logger.error("Unable to create Google Signature", e);
            throw new SignatureCreateException("Unable to create Google Signature", e);
        }
    }
}
