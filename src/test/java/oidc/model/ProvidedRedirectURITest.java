package oidc.model;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ProvidedRedirectURITest {

    @Test
    public void testCompareWithPath() {
        ProvidedRedirectURI providedRedirectURI = new ProvidedRedirectURI("http://my.domain:8080/path");

        assertTrue(providedRedirectURI.equalsIgnorePort("http://my.domain/path"));
        assertTrue(providedRedirectURI.equalsIgnorePort("http://my.domain:9090/path"));
    }

    @Test
    public void testCompareWithoutPath() {
        ProvidedRedirectURI providedRedirectURI = new ProvidedRedirectURI("http://my.domain");

        assertTrue(providedRedirectURI.equalsIgnorePort("http://my.domain"));
        assertTrue(providedRedirectURI.equalsIgnorePort("http://my.domain:9090"));
    }

    @Test
    public void testCompareNotEquals() {
        ProvidedRedirectURI providedRedirectURI = new ProvidedRedirectURI("http://my.domain");

        assertFalse(providedRedirectURI.equalsIgnorePort("https://my.domain"));
        assertFalse(providedRedirectURI.equalsIgnorePort("http://my.domain:9090/path"));
        assertFalse(providedRedirectURI.equalsIgnorePort("http://my.nope"));
    }

    @Test
    public void testLiteralCheckRequired() {
        ProvidedRedirectURI providedRedirectURI = new ProvidedRedirectURI("http://my.domain");
        assertTrue(providedRedirectURI.literalCheckRequired());

        providedRedirectURI = new ProvidedRedirectURI("http://localhost:8080/redirect");
        assertFalse(providedRedirectURI.literalCheckRequired());

        providedRedirectURI = new ProvidedRedirectURI("http://127.0.0.1:8080/redirect");
        assertFalse(providedRedirectURI.literalCheckRequired());

        //Host for this URI is null
        providedRedirectURI = new ProvidedRedirectURI("http://127.0.01:8080/redirect");
        assertTrue(providedRedirectURI.literalCheckRequired());
    }
}