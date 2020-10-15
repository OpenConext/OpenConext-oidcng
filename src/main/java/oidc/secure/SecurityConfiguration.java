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
import oidc.repository.UserRepository;
import oidc.saml.AuthenticationRequestContextResolver;
import oidc.saml.AuthnRequestConverter;
import oidc.saml.ResponseAuthenticationConverter;
import oidc.web.ConcurrentSavedRequestAwareAuthenticationSuccessHandler;
import oidc.web.FakeSamlAuthenticationFilter;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.core.io.Resource;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestContextResolver;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

@EnableScheduling
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration {

    private static final Log LOG = LogFactory.getLog(SecurityConfiguration.class);

    private static final BouncyCastleProvider bcProvider = new BouncyCastleProvider();

    static {
        Security.addProvider(bcProvider);
    }

    @Configuration
    @Order(1)
    public static class SamlSecurity extends WebSecurityConfigurerAdapter {

        private String idpEntityId;
        private String idpSsoLocation;
        private Resource idpMetadataSigningCertificatePath;
        private String spEntityId;
        private String spAcsLocation;
        private Environment environment;
        private ObjectMapper objectMapper;
        private OpenIDClientRepository openIDClientRepository;
        private UserRepository userRepository;
        private AuthenticationRequestRepository authenticationRequestRepository;
        private Resource privateKeyPath;
        private Resource certificatePath;
        private Resource oidcSamlMapping;

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
                @Value("${idp.metadata_signing_certificate_path}") Resource idpMetadataSigningCertificatePath,
                @Value("${sp.entity_id}") String spEntityId,
                @Value("${sp.acs_location}") String spAcsLocation,
                @Value("${oidc_saml_mapping_path}") Resource oidcSamlMapping) {
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
        }

        @Bean
        public AuthenticationSuccessHandler concurrentSavedRequestAwareAuthenticationSuccessHandler() {
            return new ConcurrentSavedRequestAwareAuthenticationSuccessHandler(authenticationRequestRepository);
        }

        @Bean
        public Saml2AuthenticationRequestContextResolver authenticationRequestContextResolver(RelyingPartyRegistrationRepository registrationRepository) {
            return new AuthenticationRequestContextResolver(registrationRepository.findByRegistrationId("oidcng"));
        }

        @Bean
        public Saml2AuthenticationRequestFactory authenticationRequestFactory() {
            OpenSamlAuthenticationRequestFactory authenticationRequestFactory =
                    new OpenSamlAuthenticationRequestFactory();

            AuthnRequestConverter authnRequestConverter =
                    new AuthnRequestConverter(openIDClientRepository, authenticationRequestRepository, new HttpSessionRequestCache());
            authenticationRequestFactory.setAuthenticationRequestContextConverter(authnRequestConverter);
            return authenticationRequestFactory;
        }

        @Bean
        public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
            String registrationId = "oidcng";//TODO from application.yml
            //local signing (and local decryption key and remote encryption certificate)
            Saml2X509Credential signingCredential = getSigningCredential();
            //IDP certificate for verification of incoming messages
            Saml2X509Credential idpVerificationCertificate = getVerificationCertificate();

            RelyingPartyRegistration rp = RelyingPartyRegistration
                    .withRegistrationId(registrationId)
                    .entityId(spEntityId)
                    .signingX509Credentials(c -> c.add(signingCredential))
                    .assertingPartyDetails(assertingPartyDetails -> assertingPartyDetails
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

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            OpenSamlAuthenticationProvider authenticationProvider = new OpenSamlAuthenticationProvider();
            ResponseAuthenticationConverter responseAuthenticationConverter =
                    new ResponseAuthenticationConverter(userRepository, authenticationRequestRepository, objectMapper, oidcSamlMapping);
            authenticationProvider.setResponseAuthenticationConverter(responseAuthenticationConverter);
            http.cors().configurationSource(new OidcCorsConfigurationSource()).configure(http);
            http.csrf().disable();
            http
                    .requestMatchers()
                    .antMatchers("/oidc/**","/saml2/**", "/login/**")
                    .and()
                    .authorizeRequests()
                    .antMatchers("/oidc/authorize")
                    .authenticated()
                    .and()
                    .authorizeRequests()
                    .antMatchers("/oidc/**")
                    .permitAll()
                    .and()
                    .saml2Login(saml2 -> {
                        saml2.authenticationManager(new ProviderManager(authenticationProvider));
                        AuthenticationSuccessHandler bean = getApplicationContext().getBean(AuthenticationSuccessHandler.class);
                        saml2.successHandler(bean);
                    });

            http.addFilterBefore(new MDCContextFilter(), BasicAuthenticationFilter.class);

            if (environment.acceptsProfiles(Profiles.of("dev"))) {
                http.addFilterBefore(new FakeSamlAuthenticationFilter(userRepository, objectMapper),
                        BasicAuthenticationFilter.class);
            }
        }

        @SneakyThrows
        private String read(Resource resource) {
            LOG.info("Reading resource: " + resource.getFilename());
            return IOUtils.toString(resource.getInputStream(), Charset.defaultCharset());
        }

    }


    @Configuration
    @EnableConfigurationProperties(TokenUsers.class)
    public static class AppSecurity extends WebSecurityConfigurerAdapter {

        private @Value("${manage.user}")
        String user;
        private @Value("${manage.password}")
        String password;

        @Autowired
        private TokenUsers tokenUsers;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .requestMatchers()
                    .antMatchers("/actuator/**", "/manage/**", "/tokens")
                    .and()
                    .csrf()
                    .disable()
                    .authorizeRequests()
                    .antMatchers("/actuator/health", "/actuator/info")
                    .permitAll()
                    .and()
                    .authorizeRequests()
                    .antMatchers("/manage/**", "/tokens")
                    .authenticated()
                    .and()
                    .httpBasic()
                    .and()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                    .addFilterBefore(new MDCContextFilter(), BasicAuthenticationFilter.class);
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> builder = auth
                    .inMemoryAuthentication()
                    .withUser(user)
                    .password("{noop}" + password)
                    .roles("manage")
                    .and();

            if (tokenUsers.isEnabled()) {
                tokenUsers.getUsers().forEach(user -> {
                    builder
                            .withUser(user.getUser())
                            .password("{noop}" + user.getPassword())
                            .roles("api_tokens");
                });

            }
        }
    }

}
