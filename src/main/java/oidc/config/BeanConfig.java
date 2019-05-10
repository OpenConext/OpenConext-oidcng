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
import com.nimbusds.jose.JOSEException;
import oidc.repository.UserRepository;
import oidc.secure.TokenGenerator;
import oidc.user.SamlProvisioningAuthenticationManager;
import oidc.web.ConfigurableSamlAuthenticationRequestFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.provider.service.authentication.SamlAuthenticationResponseFilter;
import org.springframework.security.saml.provider.service.config.SamlServiceProviderServerBeanConfiguration;

import javax.servlet.Filter;
import java.io.IOException;
import java.text.ParseException;

@Configuration
public class BeanConfig extends SamlServiceProviderServerBeanConfiguration {

    private AppConfig appConfiguration;
    private UserRepository userRepository;
    private ObjectMapper objectMapper;
    private String issuer;
    private String secureSecret;
    private Resource jwksKeyStorePath;

    public BeanConfig(AppConfig config,
                      UserRepository userRepository,
                      ObjectMapper objectMapper,
                      @Value("${jwks_key_store_path}") Resource jwksKeyStorePath,
                      @Value("${spring.security.saml2.service-provider.entity-id}") String issuer,
                      @Value("${secure_secret}") String secureSecret) {
        this.appConfiguration = config;
        this.userRepository = userRepository;
        this.objectMapper = objectMapper;
        this.jwksKeyStorePath = jwksKeyStorePath;
        this.issuer = issuer;
        this.secureSecret = secureSecret;
    }

    @Override
    protected SamlServerConfiguration getDefaultHostSamlServerConfiguration() {
        return appConfiguration;
    }

    @Override
    @Bean
    public Filter spSelectIdentityProviderFilter() {
        return (request, response, chain) -> chain.doFilter(request, response);
    }

    @Override
    @Bean
    public Filter spAuthenticationRequestFilter() {
        SamlProviderProvisioning<ServiceProviderService> provisioning = getSamlProvisioning();
        SamlRequestMatcher requestMatcher = new SamlRequestMatcher(provisioning, "authorize", false);
        return new ConfigurableSamlAuthenticationRequestFilter(provisioning, requestMatcher);
    }

    @Bean
    public SamlProvisioningAuthenticationManager samlProvisioningAuthenticationManager() throws IOException {
        return new SamlProvisioningAuthenticationManager(this.userRepository, this.objectMapper);
    }

    @Bean
    public TokenGenerator tokenGenerator() throws ParseException, JOSEException, IOException {
        return new TokenGenerator(jwksKeyStorePath, issuer, secureSecret);
    }

    @Override
    @Bean
    public Filter spAuthenticationResponseFilter() {
        SamlAuthenticationResponseFilter filter =
                SamlAuthenticationResponseFilter.class.cast(super.spAuthenticationResponseFilter());
        try {
            filter.setAuthenticationManager(this.samlProvisioningAuthenticationManager());
        } catch (IOException e) {
            //super has no throw clause
            throw new RuntimeException(e);
        }
        return filter;

    }
}
