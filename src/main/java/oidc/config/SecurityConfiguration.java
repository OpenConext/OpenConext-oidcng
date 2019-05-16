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

package oidc.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import oidc.repository.UserRepository;
import oidc.web.ConfigurableSamlAuthenticationRequestFilter;
import oidc.web.FakeSamlAuthenticationFilter;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.config.RotatingKeys;
import org.springframework.security.saml.provider.service.config.SamlServiceProviderSecurityConfiguration;

import java.io.IOException;
import java.nio.charset.Charset;

import static org.springframework.security.saml.provider.service.config.SamlServiceProviderSecurityDsl.serviceProvider;

@EnableWebSecurity
public class SecurityConfiguration {

    private static final Log LOG = LogFactory.getLog(SecurityConfiguration.class);

    @Configuration
    @Order(1)
    public static class SamlSecurity extends SamlServiceProviderSecurityConfiguration {

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
                            @Value("${certificate_path}") Resource certificatePath) {
            super("oidc", beanConfig);
            this.appConfiguration = appConfig;
            this.environment = environment;
            this.objectMapper = objectMapper;
            this.userRepository = userRepository;
            this.privateKeyPath = privateKeyPath;
            this.certificatePath = certificatePath;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            super.configure(http);
            http.apply(serviceProvider())
                    .configure(appConfiguration)
                    .rotatingKeys(getKeys());

            if (environment.acceptsProfiles(Profiles.of("dev"))) {
                http.addFilterBefore(new FakeSamlAuthenticationFilter(userRepository, objectMapper),
                        ConfigurableSamlAuthenticationRequestFilter.class);
            }
        }

        private RotatingKeys getKeys() throws IOException {
            String privateKey = read(this.privateKeyPath);
            String certificate = read(this.certificatePath);
            return new RotatingKeys()
                    .setActive(
                            new SimpleKey()
                                    .setName("sp-signing-key")
                                    .setPrivateKey(privateKey)
                                    .setPassphrase("sppassword")
                                    .setCertificate(certificate)
                    );
        }

        private String read(Resource resource) throws IOException {
            LOG.info("Reading resource: " + resource.getFilename());
            return IOUtils.toString(resource.getInputStream(), Charset.defaultCharset());
        }
    }


    @Configuration
    public static class AppSecurity extends WebSecurityConfigurerAdapter {

        @Value("${manage.user}")
        private String user;

        @Value("${manage.password}")
        private String password;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .csrf()
                    .disable()
                    .authorizeRequests()
                    .antMatchers("/actuator/health", "/actuator/info")
                    .permitAll()
                    .and()
                    .antMatcher("/**")
                    .authorizeRequests()
                    .antMatchers("/**")
                    .authenticated()
                    .and()
                    .httpBasic()
                    .and()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
            ;
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                    .inMemoryAuthentication()
                    .withUser(user)
                    .password("{noop}" + password)
                    .roles("manage");
        }
    }

}
