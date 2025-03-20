package oidc.web;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class URLCodingTest implements URLCoding {

    @Test(expected = IllegalArgumentException.class)
    public void decode() {
        decode("nope", "");
    }

    @Test
    public void decodeHappy() {
        assertEquals("nope", decode("nope"));
    }
}