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
import java.util.Map;

import static oidc.saml.AuthnRequestContextConsumer.REDIRECT_URI_VALID;
import static org.junit.Assert.assertEquals;

public class CustomErrorControllerTest {

    private final CustomErrorController subject = new CustomErrorController();

    @Test
    @SuppressWarnings("unchecked")
    public void error() throws URISyntaxException {
        ResponseEntity responseEntity = (ResponseEntity) doError(new InvalidScopeException("invalid_scope"));

        assertEquals(401, responseEntity.getStatusCode());
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
        assertEquals(302, responseEntity.getStatusCode());

        String location = responseEntity.getHeaders().getLocation().toString();
        assertEquals("https://oidc-playground.test2.surfconext.nl/redirect?error=access_denied&error_description=Error+description", location);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void noCookies() throws URISyntaxException {
        ModelAndView modelAndView = (ModelAndView) doError(new CookiesNotSupportedException());
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