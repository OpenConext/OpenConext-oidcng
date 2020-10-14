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
import oidc.repository.UserRepository;
import oidc.saml.AuthnRequestConverter;
import oidc.saml.CustomSaml2AuthenticationRequestContext;
import oidc.saml.ResponseAuthenticationConverter;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.env.Environment;
import org.springframework.core.io.Resource;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
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
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestContext;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestContextResolver;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

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

        private String idpAlias;
        private String[] idpMetaDataUrls;
        private String idpNameId;
        private Resource metadataSigningCertificatePath;
        private Environment environment;
        private ObjectMapper objectMapper;
        private UserRepository userRepository;
        private Resource privateKeyPath;
        private Resource certificatePath;
        private Resource oidcSamlMapping;

        public SamlSecurity(
                Environment environment,
                ObjectMapper objectMapper,
                UserRepository userRepository,
                @Value("${private_key_path}") Resource privateKeyPath,
                @Value("${certificate_path}") Resource certificatePath,
                @Value("${idp.metadata_urls}") String[] idpMetaDataUrls,
                @Value("${idp.name_id}") String idpNameId,
                @Value("${idp.metadata_signing_certificate_path}") Resource metadataSigningCertificatePath,
                @Value("${oidc_saml_mapping_path}") Resource oidcSamlMapping) {
            this.environment = environment;
            this.objectMapper = objectMapper;
            this.userRepository = userRepository;
            this.privateKeyPath = privateKeyPath;
            this.certificatePath = certificatePath;
            this.idpAlias = idpAlias;
            this.idpMetaDataUrls = idpMetaDataUrls;
            this.idpNameId = idpNameId;
            this.metadataSigningCertificatePath = metadataSigningCertificatePath;
            this.oidcSamlMapping = oidcSamlMapping;
        }

        @Bean
        public Saml2AuthenticationRequestContextResolver authenticationRequestContextResolver(RelyingPartyRegistrationRepository registrationRepository) {
            return request -> new CustomSaml2AuthenticationRequestContext(registrationRepository.findByRegistrationId("oidcng"), request);
        }

        @Bean
        public Saml2AuthenticationRequestFactory authenticationRequestFactory() {
            OpenSamlAuthenticationRequestFactory authenticationRequestFactory =
                    new OpenSamlAuthenticationRequestFactory();

            XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
            AuthnRequestBuilder authnRequestBuilder = (AuthnRequestBuilder) registry.getBuilderFactory()
                    .getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
            IssuerBuilder issuerBuilder = (IssuerBuilder) registry.getBuilderFactory()
                    .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

            AuthnRequestConverter authnRequestConverter = new AuthnRequestConverter(authnRequestBuilder, issuerBuilder);
            authenticationRequestFactory.setAuthenticationRequestContextConverter(authnRequestConverter);
            return authenticationRequestFactory;
        }

        @Bean
        public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
            //remote WebSSO Endpoint - Where to Send AuthNRequests to
            String webSsoEndpoint = "https://engine.test2.surfconext.nl/authentication/idp/single-sign-on";
            //local registration ID
            String registrationId = "oidcng";//TODO from application.yml
            //local entity ID - autogenerated based on URL
            String localEntityIdTemplate = "https://org.openconext.local.oidc.ng";//TODO application.yml
            //local SSO URL - autogenerated, endpoint to receive SAML Response objects
            String acsUrlTemplate = "http://localhost:8080/login/saml2/sso/oidcng";

            //local signing (and local decryption key and remote encryption certificate)
            Saml2X509Credential signingCredential = getSigningCredential();
            //IDP certificate for verification of incoming messages
            Saml2X509Credential idpVerificationCertificate = getVerificationCertificate();

            RelyingPartyRegistration rp = RelyingPartyRegistration
                    .withRegistrationId(registrationId)
                    .entityId(localEntityIdTemplate)
                    .signingX509Credentials(c -> c.add(signingCredential))
                    .assertingPartyDetails(assertingPartyDetails -> assertingPartyDetails
                            .entityId(idpNameId)
                            .singleSignOnServiceLocation(webSsoEndpoint)
                            .singleSignOnServiceBinding(Saml2MessageBinding.REDIRECT)
                            .wantAuthnRequestsSigned(true)
                            .verificationX509Credentials(c -> c.add(idpVerificationCertificate)))
                    .assertionConsumerServiceLocation(acsUrlTemplate)
                    .build();

            return new InMemoryRelyingPartyRegistrationRepository(rp);
        }

        private Saml2X509Credential getVerificationCertificate() {
            String certificate = KeyGenerator.keyCleanup(read(metadataSigningCertificatePath));
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
            ResponseAuthenticationConverter responseAuthenticationConverter = new ResponseAuthenticationConverter(userRepository, objectMapper, oidcSamlMapping);
            authenticationProvider.setResponseAuthenticationConverter(responseAuthenticationConverter);

            http.cors().configurationSource(new OidcCorsConfigurationSource()).configure(http);
            http.csrf().disable();
            http
                    .authorizeRequests()
                    .antMatchers("/oidc/authorize")
                    .authenticated()
                    .and()
                    .authorizeRequests()
                    .antMatchers("/oidc/**")
                    .permitAll()
                    .and()
                    .saml2Login(saml2 -> saml2.authenticationManager(new ProviderManager(authenticationProvider)));

            http.addFilterBefore(new MDCContextFilter(), BasicAuthenticationFilter.class);

//            if (environment.acceptsProfiles(Profiles.of("dev"))) {
//                http.addFilterBefore(new FakeSamlAuthenticationFilter(userRepository, objectMapper),
//                        BasicAuthenticationFilter.class);
//            }
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
                    .csrf()
                    .disable()
                    .authorizeRequests()
                    .antMatchers("/actuator/health", "/actuator/info")
                    .permitAll()
                    .and()
                    .requestMatchers()
                    .antMatchers("/manage/**", "/tokens")
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
