package com.eideasy.eseal.hsm;

import com.eideasy.eseal.SignatureCreateException;
import com.eideasy.eseal.hsm.pkcs11.PKCS11Signer;
import com.eideasy.eseal.hsm.gcloud.GoogleKmsSigner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

@Component
public class HsmSignerFactory {
    private final Environment env;

    private final Logger logger = LoggerFactory.getLogger(HsmSignerFactory.class);

    public HsmSignerFactory(@Autowired Environment env) {
        this.env = env;
    }

    public HsmSigner getSigner(String keyId) throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, KeyStoreException, IOException, SignatureCreateException {

        String keyPropertyName = "key_id." + keyId + ".hsm_implementation";
        logger.info("Getting HSM signer for key=" + keyId + ", keypropname: " + keyPropertyName);
        String implementation = env.getProperty(keyPropertyName);
        if (implementation == null) {
            throw new SignatureCreateException("HSM implementation not configured");
        }

        HsmSigner signer = null;
        switch (implementation) {
            case "pkcs11":
                signer = new PKCS11Signer();
                signer.setEnv(env);
                return signer;
            case "gcloud_hsm":
                signer = new GoogleKmsSigner();
                signer.setEnv(env);
                return signer;
        }

        throw new SignatureCreateException("Unknown HSM implementation: " + implementation);
    }

}