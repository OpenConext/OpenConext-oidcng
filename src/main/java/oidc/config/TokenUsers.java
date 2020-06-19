package oidc.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Map;

@ConfigurationProperties(prefix="token-api")
@Getter
@Setter
public class TokenUsers {

    private boolean enabled;
    private List<TokenUser> users;

    @Getter
    @Setter
    public static class TokenUser {
        private String user;
        private String password;

    }

}
