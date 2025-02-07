package oidc.exceptions;

public class BaseException extends RuntimeException {

    public BaseException(String errorMsg) {
        super(errorMsg);
    }

    public BaseException(String errorMsg, Throwable cause) {

        super(errorMsg, cause);
    }

    public String getErrorCode() {
        return getMessage();
    }

    protected boolean suppressStackTrace() {
        return false;
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        return this.suppressStackTrace() ? this : super.fillInStackTrace();
    }

    @Override
    public String toString() {
        return super.toString() + " " + getErrorCode();
    }
}
