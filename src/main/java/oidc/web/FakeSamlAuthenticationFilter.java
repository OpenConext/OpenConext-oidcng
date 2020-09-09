package oidc.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import oidc.model.User;
import oidc.repository.UserRepository;
import oidc.user.OidcSamlAuthentication;
import org.apache.commons.io.IOUtils;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.saml.saml2.authentication.Assertion;
//import org.springframework.security.saml.saml2.authentication.NameIdPrincipal;
//import org.springframework.security.saml.saml2.authentication.Subject;
//import org.springframework.security.saml.saml2.metadata.NameId;
//import org.springframework.security.saml.spi.DefaultSamlAuthentication;
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
import java.util.Collections;
import java.util.List;

public class FakeSamlAuthenticationFilter {//} extends GenericFilterBean {

//    private final UserRepository userRepository;
//    private final ObjectMapper objectMapper;
//    private final List<String> authorizeEndpoints = Arrays.asList("oidc/authorize", "oidc/consent");
//
//    public FakeSamlAuthenticationFilter(UserRepository userRepository, ObjectMapper objectMapper) {
//        this.userRepository = userRepository;
//        this.objectMapper = objectMapper;
//    }
//
//    @Override
//    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        String requestURI = ((HttpServletRequest) request).getRequestURI();
//        boolean authorizeFlow = authorizeEndpoints.stream().anyMatch(requestURI::contains);
//        if (authorizeFlow && (authentication == null || !authentication.isAuthenticated()) && !(authentication instanceof DefaultSamlAuthentication)) {
//            User user = getUser(objectMapper, request);
//            userRepository.deleteAll();
//            userRepository.insert(user);
//
//            OidcSamlAuthentication samlAuthentication = new OidcSamlAuthentication(getAssertion(), user, "http://localhost");
//            SecurityContextHolder.getContext().setAuthentication(samlAuthentication);
//        }
//        chain.doFilter(request, response);
//    }
//
//    public static User getUser(ObjectMapper objectMapper, ServletRequest request) throws IOException {
//        String userParameter = request.getParameter("user");
//        String path = String.format("data/%s.json", StringUtils.hasText(userParameter) ? userParameter : "user");
//        return objectMapper.readValue(IOUtils.toString(new ClassPathResource(path).getInputStream(), Charset.defaultCharset()), User.class);
//    }
//
//    public static Assertion getAssertion() {
//        Assertion assertion = new Assertion();
//        Subject subject = new Subject();
//
//        NameIdPrincipal principal = new NameIdPrincipal();
//        principal.setValue("urn:collab:person:example.com:admin");
//        principal.setFormat(NameId.UNSPECIFIED);
//
//        subject.setPrincipal(principal);
//
//        assertion.setSubject(subject);
//        assertion.setAttributes(Collections.emptyList());
//        return assertion;
//    }
//
}
