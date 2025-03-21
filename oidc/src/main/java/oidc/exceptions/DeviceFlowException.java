package oidc.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class DeviceFlowException extends BaseException {

    public DeviceFlowException(String message) {
        super(message);
    }

    protected boolean suppressStackTrace() {
        return true;
    }

    @Override
    public String getErrorCode() {
        return getMessage();
    }


}
