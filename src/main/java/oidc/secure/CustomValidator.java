package oidc.secure;

import org.joda.time.DateTime;
import org.springframework.security.saml.spi.DefaultValidator;
import org.springframework.security.saml.spi.SpringSecuritySaml;

public class CustomValidator extends DefaultValidator {

    public CustomValidator(SpringSecuritySaml implementation) {
        super(implementation);
    }

    @Override
    public boolean isDateTimeSkewValid(int skewMillis, int forwardMillis, DateTime time) {
        if (forwardMillis == 0) {
            return super.isDateTimeSkewValid(skewMillis, forwardMillis, time);
        }
        return true;
    }
}
