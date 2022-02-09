package oidc.config;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.jsontype.TypeDeserializer;
import oidc.model.User;
import oidc.user.OidcSamlAuthentication;
import org.springframework.security.jackson2.CoreJackson2Module;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;

import java.io.IOException;
import java.util.HashSet;
import java.util.LinkedHashMap;

public class ExtendedCoreJackson2Module extends CoreJackson2Module {

    @Override
    public void setupModule(SetupContext context) {
        //Do not call super, as JacksonMongoSessionConverter has already included this
        ObjectMapper objectMapper = context.getOwner();
        objectMapper.addMixIn(OidcSamlAuthentication.class, SimpleMixin.class);
        objectMapper.addMixIn(HashSet.class, SimpleMixin.class);
        objectMapper.addMixIn(LinkedHashMap.class, SimpleMixin.class);
        objectMapper.addMixIn(Saml2AuthenticationException.class, SimpleMixin.class);
        objectMapper.addMixIn(Saml2Error.class, SimpleMixin.class);
        objectMapper.addMixIn(User.class, SimpleMixin.class);
        objectMapper.addMixIn(Saml2Authentication.class, SimpleMixin.class);
        objectMapper.addMixIn(Saml2RedirectAuthenticationRequest.class, Saml2RedirectAuthenticationRequestMixin.class);
    }

    @Override
    public Object getTypeId() {
        return ExtendedCoreJackson2Module.class.getName();
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
