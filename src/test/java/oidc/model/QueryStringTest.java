package oidc.model;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class QueryStringTest {

    @Test
    void testStateValue() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("response_type=code&client_id=mock-sp&scope&redirect_uri=http://localhost:8091/redirect&state=https%3A%2F%2Fexample.com");
        QueryString queryString = new QueryString(request);
        assertEquals("https%3A%2F%2Fexample.com", queryString.getStateValue());
    }

    @Test
    void testStateValueNoQueryString() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        QueryString queryString = new QueryString(request);
        assertNull(queryString.getStateValue());
    }

    @Test
    void testStateValueNoState() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("response_type=code");
        QueryString queryString = new QueryString(request);
        assertNull(queryString.getStateValue());
    }
}