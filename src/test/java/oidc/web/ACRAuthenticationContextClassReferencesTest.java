package oidc.web;

import com.nimbusds.openid.connect.sdk.claims.ACR;
import org.junit.Test;
import org.springframework.security.saml.saml2.authentication.AuthenticationContextClassReference;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;

public class ACRAuthenticationContextClassReferencesTest {

    @Test
    public void test() {
        List<ACR> acrValuesObjects= Arrays.asList(new ACR("nope"));
        List<AuthenticationContextClassReference> references = acrValuesObjects.stream()
                .map(acrValue -> AuthenticationContextClassReference.fromUrn(acrValue.getValue()))
                .collect(Collectors.toList());
        assertEquals("nope", references.get(0).getValue());
    }
}
