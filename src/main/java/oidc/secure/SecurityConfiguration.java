/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package oidc.secure;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import oidc.config.OidcCorsConfigurationSource;
import oidc.config.TokenUsers;
import oidc.crypto.KeyGenerator;
import oidc.log.MDCContextFilter;
import oidc.repository.AuthenticationRequestRepository;
import oidc.repository.OpenIDClientRepository;
import oidc.repository.SamlAuthenticationRequestRepository;
import oidc.repository.UserRepository;
import oidc.saml.AuthnRequestContextConsumer;
import oidc.saml.MongoSaml2AuthenticationRequestRepository;
import oidc.saml.ResponseAuthenticationConverter;
import oidc.saml.ResponseAuthenticationValidator;
import oidc.web.ConcurrentSavedRequestAwareAuthenticationSuccessHandler;
import oidc.web.FakeSamlAuthenticationFilter;
import oidc.web.RedirectAuthenticationFailureHandler;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.metadata.OpenSaml4MetadataResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestRepository;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration {

    private static final Log LOG = LogFactory.getLog(SecurityConfiguration.class);

    private static final BouncyCastleProvider bcProvider = new BouncyCastleProvider();
    private static final String REGISTRATION_ID = "oidcng";

    static {
        Security.addProvider(bcProvider);
    }

    @Configuration
    @Order(1)
    public static class SamlSecurity {

        private final String idpEntityId;
        private final String idpSsoLocation;
        private final Resource idpMetadataSigningCertificatePath;
        private final String spEntityId;
        private final String spAcsLocation;
        private final Environment environment;
        private final ObjectMapper objectMapper;
        private final OpenIDClientRepository openIDClientRepository;
        private final UserRepository userRepository;
        private final AuthenticationRequestRepository authenticationRequestRepository;
        private final Resource privateKeyPath;
        private final Resource certificatePath;
        private final Resource oidcSamlMapping;
        private final ApplicationContext applicationContext;

        public SamlSecurity(
                Environment environment,
                ObjectMapper objectMapper,
                UserRepository userRepository,
                AuthenticationRequestRepository authenticationRequestRepository,
                OpenIDClientRepository openIDClientRepository,
                @Value("${private_key_path}") Resource privateKeyPath,
                @Value("${certificate_path}") Resource certificatePath,
                @Value("${idp.entity_id}") String idpEntityId,
                @Value("${idp.sso_location}") String idpSsoLocation,
                @Value("${idp.saml_assertion_signing_key}") Resource idpMetadataSigningCertificatePath,
                @Value("${sp.entity_id}") String spEntityId,
                @Value("${sp.acs_location}") String spAcsLocation,
                @Value("${oidc_saml_mapping_path}") Resource oidcSamlMapping,
                ApplicationContext applicationContext) {
            this.environment = environment;
            this.objectMapper = objectMapper;
            this.userRepository = userRepository;
            this.authenticationRequestRepository = authenticationRequestRepository;
            this.openIDClientRepository = openIDClientRepository;
            this.privateKeyPath = privateKeyPath;
            this.certificatePath = certificatePath;
            this.idpEntityId = idpEntityId;
            this.idpMetadataSigningCertificatePath = idpMetadataSigningCertificatePath;
            this.idpSsoLocation = idpSsoLocation;
            this.spEntityId = spEntityId;
            this.spAcsLocation = spAcsLocation;
            this.oidcSamlMapping = oidcSamlMapping;
            this.applicationContext = applicationContext;
        }

        @Bean
        public AuthenticationSuccessHandler concurrentSavedRequestAwareAuthenticationSuccessHandler() {
            return new ConcurrentSavedRequestAwareAuthenticationSuccessHandler(authenticationRequestRepository);
        }

        @Bean
        public Saml2AuthenticationRequestResolver authenticationRequestResolver(
                RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {

            OpenSaml4AuthenticationRequestResolver resolver =
                    new OpenSaml4AuthenticationRequestResolver(relyingPartyRegistrationRepository);
            AuthnRequestContextConsumer contextConsumer = new AuthnRequestContextConsumer(
                    openIDClientRepository, authenticationRequestRepository, new HttpSessionRequestCache());
            resolver.setAuthnRequestCustomizer(contextConsumer);
            return resolver;
        }

        @Bean
        public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
            //local signing (and local decryption key and remote encryption certificate)
            Saml2X509Credential signingCredential = getSigningCredential();
            //IDP certificate for verification of incoming messages
            Saml2X509Credential idpVerificationCertificate = getVerificationCertificate();

            RelyingPartyRegistration rp = RelyingPartyRegistration
                    .withRegistrationId(REGISTRATION_ID)
                    .entityId(spEntityId)
                    .signingX509Credentials(c -> c.add(signingCredential))
                    .assertingPartyMetadata(assertingPartyMetadata -> assertingPartyMetadata
                            .entityId(idpEntityId)
                            .singleSignOnServiceLocation(idpSsoLocation)
                            .singleSignOnServiceBinding(Saml2MessageBinding.REDIRECT)
                            .wantAuthnRequestsSigned(true)
                            .verificationX509Credentials(c -> c.add(idpVerificationCertificate))
                    )
                    .assertionConsumerServiceLocation(spAcsLocation)
                    .build();

            return new InMemoryRelyingPartyRegistrationRepository(rp);
        }

        private Saml2X509Credential getVerificationCertificate() {
            String certificate = KeyGenerator.keyCleanup(read(idpMetadataSigningCertificatePath));
            byte[] certBytes = KeyGenerator.getDER(certificate);
            X509Certificate x509Certificate = KeyGenerator.getCertificate(certBytes);
            return new Saml2X509Credential(x509Certificate, Saml2X509Credential.Saml2X509CredentialType.VERIFICATION);
        }

        @SneakyThrows
        private Saml2X509Credential getSigningCredential() {
            String pem;
            String certificate;
            if (this.privateKeyPath.exists() && this.certificatePath.exists()) {
                pem = read(this.privateKeyPath);
                certificate = read(this.certificatePath);
            } else {
                LOG.info("Generating public / private key pair for SAML trusted proxy");
                String[] keys = KeyGenerator.generateKeys();
                pem = keys[0];
                certificate = keys[1];
            }
            PrivateKey privateKey = KeyGenerator.readPrivateKey(pem);
            byte[] certBytes = KeyGenerator.getDER(certificate);
            X509Certificate x509Certificate = KeyGenerator.getCertificate(certBytes);

            return new Saml2X509Credential(privateKey, x509Certificate, Saml2X509Credential.Saml2X509CredentialType.SIGNING);
        }

        @Bean
        public OpenSaml4AuthenticationProvider configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
            //because Autowired this will end up in the global ProviderManager
            OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();

            ResponseAuthenticationConverter responseAuthenticationConverter =
                    new ResponseAuthenticationConverter(userRepository, authenticationRequestRepository, objectMapper, oidcSamlMapping);
            authenticationProvider.setResponseAuthenticationConverter(responseAuthenticationConverter);

            ResponseAuthenticationValidator responseValidator = new ResponseAuthenticationValidator(authenticationRequestRepository);
            authenticationProvider.setResponseValidator(responseValidator);

            auth.authenticationProvider(authenticationProvider);
            return authenticationProvider;
        }

        @Bean
        public Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> saml2AuthenticationRequestRepository(
                SamlAuthenticationRequestRepository samlAuthenticationRequestRepository,
                RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
            RelyingPartyRegistration relyingPartyRegistration = relyingPartyRegistrationRepository.findByRegistrationId(REGISTRATION_ID);
            return new MongoSaml2AuthenticationRequestRepository(samlAuthenticationRequestRepository, relyingPartyRegistration);
        }

        @Bean
        protected SecurityFilterChain samlSecurityFilterChain(HttpSecurity http) throws Exception {
            http.cors(corsConfiguration ->
                    corsConfiguration.configurationSource(new OidcCorsConfigurationSource()).configure(http));

            http
                    .securityMatcher("/oidc/**", "/saml2/**", "/login/**")
                    .csrf(AbstractHttpConfigurer::disable)
                    .authorizeHttpRequests(auth -> auth
                            .requestMatchers(HttpMethod.OPTIONS, "/oidc/authorize").permitAll()
                            .requestMatchers("/oidc/authorize", "/oidc/device_authorize").authenticated()
                            .requestMatchers("/oidc/**", "/saml2/**", "/login/**").permitAll()
                            .requestMatchers("/oidc/**").permitAll())
                    .saml2Login(saml2 -> {
                        OpenSaml4AuthenticationProvider openSamlAuthenticationProvider =
                                applicationContext.getBean(OpenSaml4AuthenticationProvider.class);
                        saml2.authenticationManager(new ProviderManager(openSamlAuthenticationProvider));
                        AuthenticationSuccessHandler bean = applicationContext.getBean(AuthenticationSuccessHandler.class);
                        saml2.successHandler(bean);
                        saml2.failureHandler(new RedirectAuthenticationFailureHandler(openIDClientRepository));
                    })
                    .addFilterBefore(new Saml2MetadataFilter(
                            req -> relyingPartyRegistrationRepository().findByRegistrationId(REGISTRATION_ID),
                            new OpenSaml4MetadataResolver()), Saml2WebSsoAuthenticationFilter.class)
                    .addFilterBefore(new MDCContextFilter(), BasicAuthenticationFilter.class);

            if (environment.acceptsProfiles(Profiles.of("dev"))) {
                http.addFilterBefore(new FakeSamlAuthenticationFilter(userRepository, objectMapper),
                        BasicAuthenticationFilter.class);
            }

            return http.build();
        }

        @SneakyThrows
        private String read(Resource resource) {
            LOG.info("Reading resource: " + resource.getFilename());
            return IOUtils.toString(resource.getInputStream(), Charset.defaultCharset());
        }

    }


    @Order(2)
    @Configuration
    @EnableConfigurationProperties(TokenUsers.class)
    public static class AppSecurity {

        private @Value("${manage.user}")
        String user;
        private @Value("${manage.password}")
        String password;

        @Autowired
        private TokenUsers tokenUsers;

        @Bean
        protected SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
            return http
                    .securityMatcher("/internal/**", "/manage/**", "/tokens", "/v2/tokens")
                    .authorizeHttpRequests(auth -> auth
                            .requestMatchers("/internal/health", "/internal/info").permitAll()
                            .requestMatchers("/manage/**", "/tokens", "/v2/tokens").permitAll()
                    )
                    .csrf(AbstractHttpConfigurer::disable)
                    .httpBasic(Customizer.withDefaults())
                    .userDetailsService(userDetailsService())
                    .sessionManagement(session ->
                            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .addFilterBefore(new MDCContextFilter(), BasicAuthenticationFilter.class)
                    .build();
        }

        public UserDetailsService userDetailsService() {
            List<UserDetails> users = new ArrayList<>();
            users.add(User.withUsername(user)
                    .password("{noop}" + password)
                    .roles("manage")
                    .build()
            );

            if (tokenUsers.isEnabled()) {
                tokenUsers.getUsers().forEach(tokenUser -> users.add(
                        User.withUsername(tokenUser.getUser())
                                .password("{noop}" + tokenUser.getPassword())
                                .roles("api_tokens")
                                .build()
                ));
            }

            return new InMemoryUserDetailsManager(users);
        }
    }

}
