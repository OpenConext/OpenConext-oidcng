package oidc.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.data.mongo.JacksonMongoSessionConverter;
import org.springframework.session.data.mongo.config.annotation.web.http.EnableMongoHttpSession;
import org.springframework.session.web.http.DefaultCookieSerializer;

import java.util.List;

@Configuration
@EnableMongoHttpSession
public class SessionConfig {

    @Bean
    DefaultCookieSerializer cookieSerializer(@Value("${secure_cookie}") boolean secureCookie) {
        DefaultCookieSerializer defaultCookieSerializer = new DefaultCookieSerializer();
        //We don't need same-site as the load-balancer takes care of this
        defaultCookieSerializer.setSameSite(null);
        defaultCookieSerializer.setUseSecureCookie(secureCookie);
        return defaultCookieSerializer;
    }

    @Bean
    JacksonMongoSessionConverter mongoSessionConverter() {
        return new JacksonMongoSessionConverter(List.of(new AuthenticationMixinModule()));
    }

}
