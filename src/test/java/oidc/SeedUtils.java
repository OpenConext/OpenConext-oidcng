package oidc;

import com.fasterxml.jackson.databind.ObjectMapper;
import oidc.model.AccessToken;
import org.apache.commons.io.IOUtils;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Date;

import static java.util.Collections.singletonList;

public interface SeedUtils {

    default AccessToken accessToken(String value, Date expiresIn) {
        return new AccessToken(value, "sub", "clientId", singletonList("openid"), "K0000001", expiresIn, false);
    }

    default AccessToken accessToken(String value, String signingKey) {
        return new AccessToken(value, "sub", "clientId", singletonList("openid"), signingKey, new Date(), false);
    }

}
