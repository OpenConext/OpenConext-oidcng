package oidc.endpoints;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import oidc.exceptions.InvalidGrantException;
import oidc.exceptions.UnauthorizedException;
import oidc.model.AccessToken;
import oidc.model.User;
import oidc.repository.AccessTokenRepository;
import oidc.secure.TokenGenerator;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.Clock;
import java.util.Map;

@RestController
public class UserInfoEndpoint implements OrderedMap {

    private AccessTokenRepository accessTokenRepository;
    private TokenGenerator tokenGenerator;

    public UserInfoEndpoint(AccessTokenRepository accessTokenRepository, TokenGenerator tokenGenerator) {
        this.accessTokenRepository = accessTokenRepository;
        this.tokenGenerator = tokenGenerator;
    }

    @GetMapping("oidc/userinfo")
    public Map<String, Object> getUserInfo(HttpServletRequest request) throws IOException, ParseException {
        return userInfo(request);
    }

    @PostMapping(value = {"oidc/userinfo"}, consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public Map<String, Object> postUserInfo(HttpServletRequest request) throws ParseException, IOException {
        return userInfo(request);
    }

    private Map<String, Object> userInfo(HttpServletRequest request) throws ParseException, IOException {
        HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
        UserInfoRequest userInfoRequest = UserInfoRequest.parse(httpRequest);

        String accessTokenValue = userInfoRequest.getAccessToken().getValue();
        AccessToken accessToken = accessTokenRepository.findByValue(accessTokenValue);

        if (accessToken.isExpired(Clock.systemDefaultZone())) {
            throw new UnauthorizedException("Access token expired");
        }
        if (accessToken.isClientCredentials()) {
            throw new InvalidGrantException("UserEndpoint not allowed for Client Credentials");
        }
        User user = tokenGenerator.decryptAccessTokenWithEmbeddedUserInfo(accessTokenValue);
        Map<String, Object> attributes = user.getAttributes();
        attributes.put("updated_at", user.getUpdatedAt());
        attributes.put("sub", user.getSub());
        return sortMap(attributes);
    }
}
