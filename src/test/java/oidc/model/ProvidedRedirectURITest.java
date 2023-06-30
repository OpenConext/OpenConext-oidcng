package oidc.model;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ProvidedRedirectURITest {

    @Test
    public void testCompareWithPath() {
        ProvidedRedirectURI providedRedirectURI = new ProvidedRedirectURI("http://my.domain:8080/path");

        assertFalse(providedRedirectURI.equalsWithLiteralCheckRequired("http://my.domain/path"));
        assertFalse(providedRedirectURI.equalsWithLiteralCheckRequired("http://my.domain:9090/path"));
    }

    @Test
    public void testCompareWithoutPath() {
        ProvidedRedirectURI providedRedirectURI = new ProvidedRedirectURI("http://my.domain");

        assertTrue(providedRedirectURI.equalsWithLiteralCheckRequired("http://my.domain"));
        assertFalse(providedRedirectURI.equalsWithLiteralCheckRequired("http://my.domain:9090"));
    }

    @Test
    public void testCompareWithFragment() {
        ProvidedRedirectURI providedRedirectURI = new ProvidedRedirectURI("http://my.domain");

        assertTrue(providedRedirectURI.equalsWithLiteralCheckRequired("http://my.domain#"));
        assertFalse(providedRedirectURI.equalsWithLiteralCheckRequired("http://my.domain#fragment"));
    }

    @Test
    public void testCompareWithQueryParams() {
        ProvidedRedirectURI providedRedirectURI = new ProvidedRedirectURI("http://my.domain?key=val");

        assertTrue(providedRedirectURI.equalsWithLiteralCheckRequired("http://my.domain?key=val"));
        assertFalse(providedRedirectURI.equalsWithLiteralCheckRequired("http://my.domain?key=nope"));
        assertFalse(providedRedirectURI.equalsWithLiteralCheckRequired("http://my.domain?key=val&key=nope"));
    }

    @Test
    public void testCompareWithoutPort() {
        ProvidedRedirectURI providedRedirectURI = new ProvidedRedirectURI("http://localhost:8080/nice");

        assertTrue(providedRedirectURI.equalsWithLiteralCheckRequired("http://localhost:9090/nice"));
    }

    @Test
    public void testCompareWithoutPortLocalHost() {
        ProvidedRedirectURI providedRedirectURI = new ProvidedRedirectURI("http://127.0.0.1:8080/nice");

        assertTrue(providedRedirectURI.equalsWithLiteralCheckRequired("http://127.0.0.1:9090/nice"));
    }

    @Test
    public void testCompareNotEquals() {
        ProvidedRedirectURI providedRedirectURI = new ProvidedRedirectURI("http://my.domain");

        assertFalse(providedRedirectURI.equalsWithLiteralCheckRequired("https://my.domain"));
        assertFalse(providedRedirectURI.equalsWithLiteralCheckRequired("http://my.domain:9090/path"));
        assertFalse(providedRedirectURI.equalsWithLiteralCheckRequired("http://my.nope"));
    }

}