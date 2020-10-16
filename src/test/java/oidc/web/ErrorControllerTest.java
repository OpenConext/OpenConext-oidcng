package oidc.web;

import oidc.exceptions.CookiesNotSupportedException;
import oidc.exceptions.InvalidScopeException;
import org.junit.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.web.servlet.ModelAndView;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class ErrorControllerTest {

    private ErrorController subject = new ErrorController();

    @Test
    @SuppressWarnings("unchecked")
    public void error() throws URISyntaxException {
        ResponseEntity responseEntity = (ResponseEntity) doError(new InvalidScopeException("invalid_scope"));

        assertEquals(401, responseEntity.getStatusCodeValue());
        Map<String, Object> body = (Map<String, Object>) responseEntity.getBody();
        assertEquals("invalid_scope", body.get("error"));
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
                .requestAttr("javax.servlet.error.exception", exception)
                .buildRequest(null);
        return subject.error(request);
    }

}