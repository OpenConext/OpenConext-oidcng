package oidc.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.mongodb.spring.session.Jackson2MongoSessionConverter;
import org.mongodb.spring.session.config.annotation.web.http.EnableMongoHttpSession;
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
    Jackson2MongoSessionConverter mongoSessionConverter() {
        return new Jackson2MongoSessionConverter(List.of(new AuthenticationMixinModule()));
    }

}
