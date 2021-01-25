package com.eideasy.eseal.hsm;

import com.eideasy.eseal.SignatureCreateException;
import org.springframework.core.env.Environment;

import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;

public abstract class HsmSigner {

    protected Environment env;

    public void setEnv(Environment env) {
        this.env = env;
    }

    public abstract String getCertificate(String keyId) throws SignatureCreateException, KeyStoreException, CertificateEncodingException;
    public abstract byte[] signDigest(String algorithm, byte[] digest, String keyId, String keyPass) throws SignatureCreateException;
}
