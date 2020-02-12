package oidc.web;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.Charset;

public interface URLCoding {

    default String decode(String s) {
        try {
            return URLDecoder.decode(s, Charset.defaultCharset().name());
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException(e);
        }
    }


}
