package oidc.config;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.module.SimpleModule;
import oidc.model.User;
import oidc.user.OidcSamlAuthentication;
import org.springframework.data.util.ReflectionUtils;
import org.springframework.security.jackson2.CoreJackson2Module;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.session.data.mongo.JacksonMongoSessionConverter;
import org.springframework.session.data.mongo.MongoSession;

import java.util.*;

public class ConfigurableJacksonMongoSessionConverter extends JacksonMongoSessionConverter {

    public ConfigurableJacksonMongoSessionConverter() {
        super();
        SimpleModule module = new CoreJackson2Module() {
            @Override
            public void setupModule(SetupContext context) {
                super.setupModule(context);
                context.setMixInAnnotations(OidcSamlAuthentication.class, SessionConfig.OidcSamlAuthenticationMixin.class);
                context.setMixInAnnotations(HashSet.class, SessionConfig.HashSetMixin.class);
                context.setMixInAnnotations(LinkedHashMap.class, SessionConfig.LinkedHashMapMixin.class);
                context.setMixInAnnotations(Saml2AuthenticationException.class, SessionConfig.Saml2AuthenticationExceptionMixin.class);
                context.setMixInAnnotations(Saml2Error.class, SessionConfig.Saml2ErrorMixin.class);
                context.setMixInAnnotations(User.class, SessionConfig.UserMixin.class);
                context.setMixInAnnotations(Saml2Authentication.class, SessionConfig.Saml2AuthenticationMixin.class);
                context.setMixInAnnotations(Saml2RedirectAuthenticationRequest.class, SessionConfig.Saml2RedirectAuthenticationRequestMixin.class);
                context.setMixInAnnotations(Saml2PostAuthenticationRequest.class, SessionConfig.Saml2PostAuthenticationRequestMixin.class);
            }
        };
        List<Module> modules = new ArrayList<>();
        modules.add(module);


    }

    private ObjectMapper buildObjectMapper() {

        ObjectMapper objectMapper = new ObjectMapper();

        // serialize fields instead of properties
        objectMapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.NONE);
        objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);

        // ignore unresolved fields (mostly 'principal')
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        objectMapper.setPropertyNamingStrategy(new CustomMongoIdNamingStrategy());

        objectMapper.registerModules(SecurityJackson2Modules.getModules(getClass().getClassLoader()));
        objectMapper.addMixIn(MongoSession.class, CustomMongoSessionMixin.class);
        objectMapper.addMixIn(HashMap.class, HashMapMixin.class);

        return objectMapper;
    }

    private static class CustomMongoSessionMixin {

        @JsonCreator
        CustomMongoSessionMixin(@JsonProperty("_id") String id,
                          @JsonProperty("intervalSeconds") long maxInactiveIntervalInSeconds) {
        }

    }

    /**
     * Used to whitelist {@link HashMap} for {@link SecurityJackson2Modules}.
     */
    private static class HashMapMixin {

        // Nothing special

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

    private static class CustomMongoIdNamingStrategy extends PropertyNamingStrategy.PropertyNamingStrategyBase {

        @Override
        public String translate(String propertyName) {

            switch (propertyName) {
                case "id":
                    return "_id";
                case "_id":
                    return "id";
                default:
                    return propertyName;
            }
        }

    }

}
