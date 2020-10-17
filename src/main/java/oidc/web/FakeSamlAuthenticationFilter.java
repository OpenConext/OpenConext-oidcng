package oidc.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import oidc.model.User;
import oidc.repository.UserRepository;
import oidc.user.OidcSamlAuthentication;
import org.apache.commons.io.IOUtils;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectBuilder;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.List;

import static oidc.saml.AuthnRequestConverter.REDIRECT_URI_VALID;

public class FakeSamlAuthenticationFilter extends GenericFilterBean {

    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;
    private final List<String> authorizeEndpoints = Arrays.asList("oidc/authorize", "oidc/consent");
    private final XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);

    public FakeSamlAuthenticationFilter(UserRepository userRepository, ObjectMapper objectMapper) {
        this.userRepository = userRepository;
        this.objectMapper = objectMapper;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String requestURI = ((HttpServletRequest) request).getRequestURI();
        boolean authorizeFlow = authorizeEndpoints.stream().anyMatch(requestURI::contains);
        if (authorizeFlow && (authentication == null || !authentication.isAuthenticated()) && !(authentication instanceof OidcSamlAuthentication)) {
            User user = getUser(objectMapper, request);
            userRepository.deleteAll();
            userRepository.insert(user);

            request.setAttribute(REDIRECT_URI_VALID, true);

            OidcSamlAuthentication samlAuthentication = new OidcSamlAuthentication(getAssertion(), user, "http://localhost");
            SecurityContextHolder.getContext().setAuthentication(samlAuthentication);
        }
        chain.doFilter(request, response);
    }

    public User getUser(ObjectMapper objectMapper, ServletRequest request) throws IOException {
        String userParameter = request.getParameter("user");
        String path = String.format("data/%s.json", StringUtils.hasText(userParameter) ? userParameter : "user");
        return objectMapper.readValue(IOUtils.toString(new ClassPathResource(path).getInputStream(), Charset.defaultCharset()), User.class);
    }

    public Assertion getAssertion() {
        AssertionBuilder assertionBuilder = (AssertionBuilder) registry.getBuilderFactory()
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        Assertion assertion = assertionBuilder.buildObject();
        SubjectBuilder subjectBuilder = (SubjectBuilder) registry.getBuilderFactory()
                .getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        Subject subject = subjectBuilder.buildObject();

        NameIDBuilder nameIDBuilder = (NameIDBuilder) registry.getBuilderFactory().getBuilder(NameID.DEFAULT_ELEMENT_NAME);

        NameID nameID = nameIDBuilder.buildObject();
        nameID.setValue("urn:collab:person:example.com:admin");

        subject.setNameID(nameID);
        assertion.setSubject(subject);
        return assertion;
    }

}
