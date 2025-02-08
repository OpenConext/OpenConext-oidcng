package oidc.saml;

import net.shibboleth.shared.xml.XMLParserException;
import oidc.model.AuthenticationRequest;
import oidc.repository.AuthenticationRequestRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml5AuthenticationProvider;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Date;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

class ResponseAuthenticationValidatorTest extends AbstractSamlUnitTest {

    private final AuthenticationRequestRepository authenticationRequestRepository = mock(AuthenticationRequestRepository.class);

    private final ResponseAuthenticationValidator subject = new ResponseAuthenticationValidator(authenticationRequestRepository);

    @BeforeEach
    public void before() {
        reset(authenticationRequestRepository);
    }

    @Test
    void convert() throws XMLParserException, IOException, ClassNotFoundException, UnmarshallingException, InvocationTargetException, NoSuchMethodException, InstantiationException, IllegalAccessException {
        OpenSaml5AuthenticationProvider.ResponseToken responseToken = getResponseToken("saml/no_assertion_response.xml");
        when(authenticationRequestRepository.findById(anyString())).thenReturn(Optional.of(
                new AuthenticationRequest("id", new Date(), "clientId", "http://some")));
        assertThrows(ContextSaml2AuthenticationException.class, () -> subject.convert(responseToken));
    }

}