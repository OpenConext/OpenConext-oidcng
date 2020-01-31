package oidc.config;

import oidc.AbstractIntegrationTest;
import oidc.secure.CustomValidator;
import org.joda.time.DateTime;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.SamlValidator;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class CustomValidatorTest extends AbstractIntegrationTest {

    @Autowired
    protected SamlValidator samlValidator;

    @Test
    public void isDateTimeSkewValid() {
        CustomValidator validator = (CustomValidator) samlValidator;
        DateTime authnInstant = DateTime.now().minusDays(5 * 365);
        DateTime issueInstant = DateTime.now().minusDays(365);

        assertFalse(validator.isDateTimeSkewValid(validator.getResponseSkewTimeMillis(), 0, issueInstant));
        assertTrue(validator.isDateTimeSkewValid(validator.getResponseSkewTimeMillis(), validator.getMaxAuthenticationAgeMillis(), authnInstant));
    }
}
