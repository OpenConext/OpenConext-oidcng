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
import oidc.config.AppConfig;
import oidc.config.BeanConfig;
import oidc.config.OidcCorsConfigurationSource;
import oidc.config.TokenUsers;
import oidc.crypto.KeyGenerator;
import oidc.log.MDCContextFilter;
import oidc.repository.UserRepository;
import oidc.web.ConfigurableSamlAuthenticationRequestFilter;
import oidc.web.FakeSamlAuthenticationFilter;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.config.RotatingKeys;
import org.springframework.security.saml.provider.service.config.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.service.config.SamlServiceProviderSecurityConfiguration;
import org.springframework.security.saml.provider.service.config.SamlServiceProviderSecurityDsl;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.nio.charset.Charset;
import java.util.Collections;
import java.util.stream.Stream;

import static org.springframework.security.saml.provider.service.config.SamlServiceProviderSecurityDsl.serviceProvider;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration {

    private static final Log LOG = LogFactory.getLog(SecurityConfiguration.class);

    @Configuration
    @Order(1)
    public static class SamlSecurity extends SamlServiceProviderSecurityConfiguration {

        private String idpAlias;
        private String[] idpMetaDataUrls;
        private String idpNameId;
        private Resource metadataSigningCertificatePath;
        private Environment environment;
        private AppConfig appConfiguration;
        private ObjectMapper objectMapper;
        private UserRepository userRepository;
        private Resource privateKeyPath;
        private Resource certificatePath;

        public SamlSecurity(BeanConfig beanConfig,
                            @Qualifier("appConfig") AppConfig appConfig,
                            Environment environment,
                            ObjectMapper objectMapper,
                            UserRepository userRepository,
                            @Value("${private_key_path}") Resource privateKeyPath,
                            @Value("${certificate_path}") Resource certificatePath,
                            @Value("${idp.alias}") String idpAlias,
                            @Value("${idp.metadata_urls}") String[] idpMetaDataUrls,
                            @Value("${idp.name_id}") String idpNameId,
                            @Value("${idp.metadata_signing_certificate_path}") Resource metadataSigningCertificatePath) {
            super("oidc", beanConfig);
            this.appConfiguration = appConfig;
            this.environment = environment;
            this.objectMapper = objectMapper;
            this.userRepository = userRepository;
            this.privateKeyPath = privateKeyPath;
            this.certificatePath = certificatePath;
            this.idpAlias = idpAlias;
            this.idpMetaDataUrls = idpMetaDataUrls;
            this.idpNameId = idpNameId;
            this.metadataSigningCertificatePath = metadataSigningCertificatePath;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            super.configure(http);
            http.cors().configurationSource(new OidcCorsConfigurationSource()).configure(http);

            SamlServiceProviderSecurityDsl samlServiceProviderSecurityDsl = http.apply(serviceProvider());
            samlServiceProviderSecurityDsl
                    .configure(appConfiguration)
                    .rotatingKeys(getKeys());
            Stream.of(this.idpMetaDataUrls).map(String::trim).forEach(idpMetaDataUrl -> {
                ExternalIdentityProviderConfiguration idp = new ExternalIdentityProviderConfiguration();
                idp.setAssertionConsumerServiceIndex(0)
                        .setNameId(idpNameId)
                        .setMetadataTrustCheck(true)
                        .setAlias(idpAlias)
                        .setVerificationKeys(Collections.singletonList(strip(read(metadataSigningCertificatePath))))
                        .setMetadata(idpMetaDataUrl);
                samlServiceProviderSecurityDsl.identityProvider(idp);
            });
            http.addFilterBefore(new MDCContextFilter(), BasicAuthenticationFilter.class);

            if (environment.acceptsProfiles(Profiles.of("dev"))) {
                http.addFilterBefore(new FakeSamlAuthenticationFilter(userRepository, objectMapper),
                        ConfigurableSamlAuthenticationRequestFilter.class);
            }
        }



        private RotatingKeys getKeys() throws Exception {
            String privateKey;
            String certificate;
            if (this.privateKeyPath.exists() && this.certificatePath.exists()) {
                privateKey = read(this.privateKeyPath);
                certificate = read(this.certificatePath);
            } else {
                LOG.info("Generating public / private key pair for SAML trusted proxy");
                String[] keys = KeyGenerator.generateKeys();
                privateKey = keys[0];
                certificate = keys[1];
            }
            return new RotatingKeys()
                    .setActive(
                            new SimpleKey()
                                    .setName("sp-signing-key")
                                    .setPrivateKey(privateKey)
                                    //to prevent null-pointer in SamlKeyStoreProvider
                                    .setPassphrase("")
                                    .setCertificate(certificate)
                    );
        }

        @SneakyThrows
        private String read(Resource resource) {
            LOG.info("Reading resource: " + resource.getFilename());
            return IOUtils.toString(resource.getInputStream(), Charset.defaultCharset());
        }

        private String strip(String certificate) {
            return certificate
                    .replaceAll("-----BEGIN CERTIFICATE-----", "")
                    .replaceAll("-----END CERTIFICATE-----", "")
                    .replaceAll("[\n\t\r ]", "");
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
