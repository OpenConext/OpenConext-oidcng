package oidc.web;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.Charset;

public interface URLCoding {

    default String decode(String s) {
        return decode(s, Charset.defaultCharset().name());
    }

    default String decode(String s, String enc) {
        try {
            return URLDecoder.decode(s, enc);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException(e);
        }
    }

}
