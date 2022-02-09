package oidc.config;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.module.SimpleModule;
import oidc.model.User;
import oidc.user.OidcSamlAuthentication;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.jackson2.CoreJackson2Module;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.SessionRepository;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;
import org.springframework.session.data.mongo.JacksonMongoSessionConverter;
import org.springframework.session.data.mongo.config.annotation.web.http.EnableMongoHttpSession;
import org.springframework.session.web.context.AbstractHttpSessionApplicationInitializer;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

import java.util.*;

@Configuration
@EnableMongoHttpSession
//@EnableSpringHttpSession
public class SessionConfig extends AbstractHttpSessionApplicationInitializer {

    @Bean
    CookieSerializer cookieSerializer(@Value("${secure_cookie}") boolean secureCookie) {
        DefaultCookieSerializer defaultCookieSerializer = new DefaultCookieSerializer();
        //We don't need same-site as the load-balancer takes care of this
        defaultCookieSerializer.setSameSite("Lax");
        defaultCookieSerializer.setUseSecureCookie(secureCookie);
        return defaultCookieSerializer;
    }

//    @Bean
//    @Primary
//    SessionRepository sessionRepository() {
//        return new MapSessionRepository(new HashMap<>());
//    }

    @Bean
    JacksonMongoSessionConverter mongoSessionConverter() {
        return new ConfigurableJacksonMongoSessionConverter();
    }


}
