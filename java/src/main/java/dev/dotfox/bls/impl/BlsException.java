package dev.dotfox.bls.impl;

public class BlsException extends IllegalArgumentException {

    public BlsException(String message) {
        super(message);
    }

    public BlsException(String message, Throwable cause) {
        super(message, cause);
    }
}
