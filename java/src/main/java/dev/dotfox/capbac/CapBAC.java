package dev.dotfox.capbac;

public class CapBAC {
    public static class SignatureError extends RuntimeException{
        SignatureError(Throwable cause) {
            super(cause);
        }
    }

    public static class Error extends Throwable {
        Error() {
        }

        Error(Throwable cause) {
            super(cause);
        }

        Error(String msg) {
            super(msg);
        }
    }
    public static class Malformed extends Error {
        Malformed(Throwable cause) {
            super(cause);
        }
    }

    public static class Invalid extends Error {
        Invalid(String msg) {
            super(msg);
        }
    }

    public static class Expired extends Error {

    }

    public static class BadID extends Error {
        BadID(Throwable cause) {
            super(cause);
        }

        BadID() {
            super();
        }

        BadID(String msg) {
            super(msg);
        }
    }

    public static class BadSign extends Error {
        BadSign() {
            super();
        }

        BadSign(Throwable cause) {
            super(cause);
        }

        BadSign(String msg) {
            super(msg);
        }
    }

    static void runtimeCheck(boolean res, String message) {
        if (!res) {
            throw new RuntimeException(message);
        }
    }
}
