package oidc.web;

import oidc.exceptions.InvalidScopeException;
import org.junit.Test;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class ErrorControllerTest {

    private ErrorController subject = new ErrorController(new DefaultErrorAttributes(true));

    @Test
    public void error() throws URISyntaxException, UnsupportedEncodingException {
        MockHttpServletRequest request = MockMvcRequestBuilders
                .get(new URI("http://localhost:8080/oidc/authorize?response_type=code&client_id=http@//mock-sp&scope=openid&redirect_uri=http://localhost:8080"))
                .requestAttr("javax.servlet.error.exception", new InvalidScopeException("invalid scope"))
                .buildRequest(null);
        ResponseEntity responseEntity = subject.error(request);

        assertEquals(401, responseEntity.getStatusCodeValue());
        Map<String, Object> body = (Map<String, Object>) responseEntity.getBody();
        assertEquals("Bad request", body.get("error"));
    }
}