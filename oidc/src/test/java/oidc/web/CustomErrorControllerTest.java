package oidc.web;

import oidc.exceptions.CookiesNotSupportedException;
import oidc.exceptions.InvalidScopeException;
import oidc.model.AuthenticationRequest;
import oidc.saml.ContextSaml2AuthenticationException;
import org.junit.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.web.servlet.ModelAndView;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static oidc.saml.AuthnRequestContextConsumer.REDIRECT_URI_VALID;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class CustomErrorControllerTest {

    private final CustomErrorController subject = new CustomErrorController();

    @Test
    @SuppressWarnings("unchecked")
    public void error() throws URISyntaxException {
        ResponseEntity responseEntity = (ResponseEntity) doError(new InvalidScopeException("invalid_scope"));

        assertEquals(401, responseEntity.getStatusCode().value());
        Map<String, Object> body = (Map<String, Object>) responseEntity.getBody();
        assertEquals("invalid_scope", body.get("error"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void errorAuthorizationRequestContext() throws URISyntaxException {
        String originalUrl = "http://localhost:9195/oidc/authorize?scope=openid&acr_values=https://eduid.nl/trust/affiliation-student&response_type=code&redirect_uri=https://oidc-playground.test2.surfconext.nl/redirect&state=example&prompt=login&nonce=example&client_id=playground_client&response_mode=query";
        ContextSaml2AuthenticationException exception = new ContextSaml2AuthenticationException(new AuthenticationRequest("id", new Date(), "client_id", originalUrl), "Error description");
        MockHttpServletRequest request = MockMvcRequestBuilders
                .get(new URI("http://localhost:8080/oidc/authorize?response_type=code&client_id=http@//mock-sp&scope=openid&redirect_uri=http://localhost:8080"))
                .requestAttr("jakarta.servlet.error.exception", exception)
                .buildRequest(null);
        request.setAttribute(REDIRECT_URI_VALID, true);
        ResponseEntity responseEntity = (ResponseEntity) subject.error(request);
        assertEquals(302, responseEntity.getStatusCode().value());

        String location = responseEntity.getHeaders().getLocation().toString();
        assertEquals("https://oidc-playground.test2.surfconext.nl/redirect?error=access_denied&error_description=Error+description", location);
    }

    @Test
    public void stateCanNotInjectParameters() throws URISyntaxException {
        for (String responseMode : List.of("query", "fragment")) {
            MockHttpServletRequest request = MockMvcRequestBuilders
                    .get(new URI("http://localhost:8080/oidc/authorize?response_type=code&client_id=mock-sp&scope=openid" +
                            "&redirect_uri=http://localhost:8080/redirect&response_mode=" + responseMode +
                            "&state=abc%26code%3Dinjected"))
                    .requestAttr("jakarta.servlet.error.exception", new InvalidScopeException("invalid_scope"))
                    .buildRequest(null);
            request.setAttribute(REDIRECT_URI_VALID, true);
            ResponseEntity responseEntity = (ResponseEntity) subject.error(request);

            String location = responseEntity.getHeaders().getLocation().toString();
            assertTrue(location, location.endsWith("&state=abc%26code%3Dinjected"));
            assertFalse(location, location.contains("&code=injected"));
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    public void noCookies() throws URISyntaxException {
        ModelAndView modelAndView = (ModelAndView) doError(new CookiesNotSupportedException("test"));
        assertEquals("no_session_found", modelAndView.getViewName());
    }

    private Object doError(Exception exception) throws URISyntaxException {
        MockHttpServletRequest request = MockMvcRequestBuilders
                .get(new URI("http://localhost:8080/oidc/authorize?response_type=code&client_id=http@//mock-sp&scope=openid&redirect_uri=http://localhost:8080"))
                .requestAttr("jakarta.servlet.error.exception", exception)
                .buildRequest(null);
        return subject.error(request);
    }

}
