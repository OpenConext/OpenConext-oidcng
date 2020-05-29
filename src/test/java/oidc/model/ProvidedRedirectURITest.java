package oidc.model;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ProvidedRedirectURITest {

    @Test
    public void testCompareWithPath() {
        ProvidedRedirectURI providedRedirectURI = new ProvidedRedirectURI("http://my.domain:8080/path", true);

        assertTrue(providedRedirectURI.equalsIgnorePort("http://my.domain/path"));
        assertTrue(providedRedirectURI.equalsIgnorePort("http://my.domain:9090/path"));
    }

    @Test
    public void testCompareWithoutPath() {
        ProvidedRedirectURI providedRedirectURI = new ProvidedRedirectURI("http://my.domain", true);

        assertTrue(providedRedirectURI.equalsIgnorePort("http://my.domain"));
        assertTrue(providedRedirectURI.equalsIgnorePort("http://my.domain:9090"));
    }

    @Test
    public void testCompareNotEquasl() {
        ProvidedRedirectURI providedRedirectURI = new ProvidedRedirectURI("http://my.domain", true);

        assertFalse(providedRedirectURI.equalsIgnorePort("https://my.domain"));
        assertFalse(providedRedirectURI.equalsIgnorePort("http://my.domain:9090/path"));
        assertFalse(providedRedirectURI.equalsIgnorePort("http://my.nope"));
    }
}