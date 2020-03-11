package oidc.web;

import org.junit.Test;

import static org.junit.Assert.*;

public class URLCodingTest implements URLCoding {

    @Test(expected = IllegalArgumentException.class)
    public void decode() {
        decode("nope", "");
    }
}