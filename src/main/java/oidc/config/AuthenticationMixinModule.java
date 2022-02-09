package oidc.config;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.jsontype.TypeDeserializer;
import com.fasterxml.jackson.databind.module.SimpleModule;
import oidc.model.User;
import oidc.user.OidcSamlAuthentication;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;

import java.io.IOException;
import java.util.HashSet;
import java.util.LinkedHashMap;

public class AuthenticationMixinModule extends SimpleModule {

    public AuthenticationMixinModule() {
        super.setMixInAnnotation(OidcSamlAuthentication.class, SimpleMixin.class);
        super.setMixInAnnotation(HashSet.class, SimpleMixin.class);
        super.setMixInAnnotation(LinkedHashMap.class, SimpleMixin.class);
        super.setMixInAnnotation(Saml2AuthenticationException.class, SimpleMixin.class);
        super.setMixInAnnotation(Saml2Error.class, SimpleMixin.class);
        super.setMixInAnnotation(User.class, SimpleMixin.class);
        super.setMixInAnnotation(Saml2Authentication.class, SimpleMixin.class);
        super.setMixInAnnotation(Saml2RedirectAuthenticationRequest.class, Saml2RedirectAuthenticationRequestMixin.class);
    }

    private static class SimpleMixin {
    }

    @JsonDeserialize(using = Saml2RedirectAuthenticationRequestDeserializer.class)
    private static class Saml2RedirectAuthenticationRequestMixin {
    }

    public static class Saml2RedirectAuthenticationRequestDeserializer extends JsonDeserializer<Saml2RedirectAuthenticationRequest> {

        @Override
        public Saml2RedirectAuthenticationRequest deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JacksonException {
            //We are not interested in the values and construction is not possible due to private, not-null fields
            return null;
        }

        @Override
        public Object deserializeWithType(JsonParser p, DeserializationContext ctxt, TypeDeserializer typeDeserializer) throws IOException, JacksonException {
            return this.deserialize(p, ctxt);
        }
    }

}
