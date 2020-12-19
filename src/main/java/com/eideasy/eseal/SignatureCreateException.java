package com.eideasy.eseal;

public class SignatureCreateException extends Throwable {
    public SignatureCreateException(String message) {
        super(message);
    }

    public SignatureCreateException(String message, Throwable cause) {
        super(message, cause);
    }
}
