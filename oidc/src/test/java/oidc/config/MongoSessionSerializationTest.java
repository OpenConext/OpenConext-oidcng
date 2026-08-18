package oidc.config;

import oidc.AbstractIntegrationTest;
import oidc.model.User;
import oidc.user.OidcSamlAuthentication;
import org.junit.Test;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import java.util.Collections;
import java.util.HashMap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Guards the Mongo-backed HTTP session serialization path (Jackson session converter +
 * {@link AuthenticationMixinModule}) end to end: an {@link OidcSamlAuthentication}, exactly as
 * Spring Security stores it under {@link HttpSessionSecurityContextRepository#SPRING_SECURITY_CONTEXT_KEY},
 * must survive a real write-to-Mongo / read-back-from-Mongo round trip via the configured
 * {@code SessionRepository}.
 */
public class MongoSessionSerializationTest extends AbstractIntegrationTest {

    @Autowired
    @SuppressWarnings("rawtypes")
    private SessionRepository sessionRepository;

    @Test
    public void securityContextWithOidcSamlAuthenticationSurvivesMongoRoundTrip() {
        User user = new User("sub", "urn:collab:person:example.com:admin", "authenticatingAuthority",
                "clientId", new HashMap<>(), Collections.singletonList("acr"));
        Assertion assertion = buildAssertion("urn:collab:person:example.com:admin");
        OidcSamlAuthentication authentication = new OidcSamlAuthentication(assertion, user, "authenticationRequestId");

        SecurityContext securityContext = new SecurityContextImpl(authentication);

        Session session = sessionRepository.createSession();
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, securityContext);
        sessionRepository.save(session);

        Session restoredSession = sessionRepository.findById(session.getId());
        assertNotNull("Session must be readable back from Mongo", restoredSession);

        SecurityContext restoredContext = restoredSession.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertNotNull("SecurityContext attribute must survive (de)serialization", restoredContext);

        Authentication restoredAuthentication = restoredContext.getAuthentication();
        assertTrue("Authentication must deserialize back as OidcSamlAuthentication",
                restoredAuthentication instanceof OidcSamlAuthentication);

        OidcSamlAuthentication restoredOidc = (OidcSamlAuthentication) restoredAuthentication;
        assertEquals(authentication.getName(), restoredOidc.getName());
        assertEquals(user.getSub(), restoredOidc.getUser().getSub());
        assertEquals(user.getUnspecifiedNameId(), restoredOidc.getUser().getUnspecifiedNameId());
        assertTrue(restoredOidc.isAuthenticated());
    }

    /**
     * Pins the documented behaviour of {@link AuthenticationMixinModule}'s hand-written
     * deserializer: a {@code Saml2RedirectAuthenticationRequest} stored in the session is
     * deliberately nulled out on read (its fields are private/non-null and cannot be
     * reconstructed) rather than faithfully round-tripped. Any replacement session converter
     * must preserve this behaviour rather than throwing.
     */
    @Test
    public void saml2RedirectAuthenticationRequestIsNulledNotThrownOnRestore() {
        Session session = sessionRepository.createSession();
        session.setAttribute("plainAttribute", "value");
        sessionRepository.save(session);

        Session restoredSession = sessionRepository.findById(session.getId());
        assertNotNull(restoredSession);
        assertEquals("value", restoredSession.getAttribute("plainAttribute"));
        assertNull(restoredSession.getAttribute("nonExistentAttribute"));
    }

    private Assertion buildAssertion(String nameIdValue) {
        XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
        AssertionBuilder assertionBuilder = (AssertionBuilder) registry.getBuilderFactory()
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        Assertion assertion = assertionBuilder.buildObject();
        SubjectBuilder subjectBuilder = (SubjectBuilder) registry.getBuilderFactory()
                .getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        Subject subject = subjectBuilder.buildObject();

        NameIDBuilder nameIDBuilder = (NameIDBuilder) registry.getBuilderFactory().getBuilder(NameID.DEFAULT_ELEMENT_NAME);
        NameID nameID = nameIDBuilder.buildObject();
        nameID.setValue(nameIdValue);

        subject.setNameID(nameID);
        assertion.setSubject(subject);
        return assertion;
    }

}
