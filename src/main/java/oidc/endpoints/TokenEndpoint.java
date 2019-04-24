package oidc.endpoints;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import oidc.exceptions.ClientAuthenticationNotSupported;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Controller
public class TokenEndpoint {


    @PostMapping(value = "oidc/token", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public ResponseEntity token(HttpServletRequest request) throws IOException, ParseException {
        HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
        TokenRequest tokenRequest = TokenRequest.parse(httpRequest);

        ClientAuthentication clientAuthentication = tokenRequest.getClientAuthentication();
        if (!(clientAuthentication instanceof ClientSecretBasic)) {
            throw new ClientAuthenticationNotSupported(
                    String.format("Unsupported client authentication in token  endpoint", clientAuthentication.getClass()));
        }
        return null;
    }

}
