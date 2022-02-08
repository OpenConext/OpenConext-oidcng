package oidc.config;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.module.SimpleModule;
import oidc.model.User;
import oidc.user.OidcSamlAuthentication;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.jackson2.CoreJackson2Module;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.session.data.mongo.JacksonMongoSessionConverter;
import org.springframework.session.data.mongo.config.annotation.web.http.EnableMongoHttpSession;
import org.springframework.session.web.context.AbstractHttpSessionApplicationInitializer;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;

@Configuration
@EnableMongoHttpSession
public class SessionConfig extends AbstractHttpSessionApplicationInitializer {

    @Bean
    CookieSerializer cookieSerializer(@Value("${secure_cookie}") boolean secureCookie) {
        DefaultCookieSerializer defaultCookieSerializer = new DefaultCookieSerializer();
        //We don't need same-site as the load-balancer takes care of this
        defaultCookieSerializer.setSameSite(null);
        defaultCookieSerializer.setUseSecureCookie(secureCookie);
        return defaultCookieSerializer;
    }

    @Bean
    JacksonMongoSessionConverter mongoSessionConverter() {
        SimpleModule module = new CoreJackson2Module() {
            @Override
            public void setupModule(SetupContext context) {
                super.setupModule(context);
                context.setMixInAnnotations(OidcSamlAuthentication.class, OidcSamlAuthenticationMixin.class);
                context.setMixInAnnotations(HashSet.class, HashSetMixin.class);
                context.setMixInAnnotations(LinkedHashMap.class, LinkedHashMapMixin.class);
                context.setMixInAnnotations(Saml2AuthenticationException.class, Saml2AuthenticationExceptionMixin.class);
                context.setMixInAnnotations(Saml2Error.class, Saml2ErrorMixin.class);
                context.setMixInAnnotations(User.class, UserMixin.class);
                context.setMixInAnnotations(Saml2Authentication.class, Saml2AuthenticationMixin.class);
                context.setMixInAnnotations(Saml2RedirectAuthenticationRequest.class, Saml2RedirectAuthenticationRequestMixin.class);
                context.setMixInAnnotations(Saml2PostAuthenticationRequest.class, Saml2PostAuthenticationRequestMixin.class);
            }
        };

        List<Module> modules = new ArrayList<>();
        modules.add(module);

        return new JacksonMongoSessionConverter(modules);
    }

    private static class Saml2AuthenticationMixin {

    }

    private static class OidcSamlAuthenticationMixin {
    }

    private static class HashSetMixin {
    }

    private static class Saml2AuthenticationExceptionMixin {
    }

    private static class Saml2ErrorMixin {
    }

    private static class LinkedHashMapMixin {
    }

    private static class UserMixin {
    }

    private static class Saml2RedirectAuthenticationRequestMixin {
    }

    private static class Saml2PostAuthenticationRequestMixin {
    }

}
