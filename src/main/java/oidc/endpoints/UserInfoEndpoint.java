package oidc.endpoints;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import oidc.exceptions.InvalidGrantException;
import oidc.log.MDCContext;
import oidc.model.AccessToken;
import oidc.model.User;
import oidc.repository.AccessTokenRepository;
import oidc.secure.TokenGenerator;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.CollectionUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.Clock;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

@RestController
public class UserInfoEndpoint {

    private AccessTokenRepository accessTokenRepository;
    private TokenGenerator tokenGenerator;

    public UserInfoEndpoint(AccessTokenRepository accessTokenRepository, TokenGenerator tokenGenerator) {
        this.accessTokenRepository = accessTokenRepository;
        this.tokenGenerator = tokenGenerator;
    }

    @GetMapping("oidc/userinfo")
    public ResponseEntity<Map<String, Object>> getUserInfo(HttpServletRequest request) throws IOException, ParseException, java.text.ParseException {
        return userInfo(request);
    }

    @PostMapping(value = {"oidc/userinfo"}, consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public ResponseEntity<Map<String, Object>> postUserInfo(HttpServletRequest request) throws ParseException, IOException, java.text.ParseException {
        return userInfo(request);
    }

    private ResponseEntity<Map<String, Object>> userInfo(HttpServletRequest request) throws ParseException, IOException, java.text.ParseException {
        HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
        UserInfoRequest userInfoRequest = UserInfoRequest.parse(httpRequest);

        String accessTokenValue = userInfoRequest.getAccessToken().getValue();

        MDCContext.mdcContext("action", "Userinfo", "accessTokenValue", accessTokenValue);

        Optional<SignedJWT> optionalSignedJWT = tokenGenerator.parseAndValidateSignedJWT(accessTokenValue);
        if (!optionalSignedJWT.isPresent()) {
            return errorResponse("Access Token not found");
        }
        SignedJWT signedJWT = optionalSignedJWT.get();
        String jwtId = signedJWT.getJWTClaimsSet().getJWTID();
        Optional<AccessToken> optionalAccessToken = accessTokenRepository.findByJwtId(jwtId);

        if (!optionalAccessToken.isPresent()) {
            return errorResponse("Access Token not found");
        }
        AccessToken accessToken = optionalAccessToken.get();
        if (accessToken.isExpired(Clock.systemDefaultZone())) {
            return errorResponse("Access Token expired");
        }
        if (accessToken.isClientCredentials()) {
            throw new InvalidGrantException("UserEndpoint not allowed for Client Credentials");
        }
        User user = tokenGenerator.decryptAccessTokenWithEmbeddedUserInfo(signedJWT);

        MDCContext.mdcContext(user);

        Map<String, Object> attributes = user.getAttributes();
        List<String> acrClaims = user.getAcrClaims();
        if (!CollectionUtils.isEmpty(acrClaims)) {
            attributes.put("acr", String.join(" ", acrClaims));
        }
        attributes.put("updated_at", user.getUpdatedAt());
        attributes.put("sub", user.getSub());
        return ResponseEntity.ok(new TreeMap<>(attributes));
    }

    private ResponseEntity<Map<String, Object>> errorResponse(String errorDescription) {
        Map<String, Object> body = new HashMap<>();
        body.put("error", "invalid_token");
        body.put("error_description", errorDescription);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }
}
