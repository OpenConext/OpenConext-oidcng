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

import com.nimbusds.jose.JOSEException;
import oidc.repository.UserRepository;
import oidc.secure.TokenGenerator;
import oidc.user.SamlProvisioningAuthenticationManager;
import oidc.web.ConfigurableSamlAuthenticationRequestFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.provider.service.authentication.SamlAuthenticationResponseFilter;
import org.springframework.security.saml.provider.service.config.SamlServiceProviderServerBeanConfiguration;
import org.springframework.security.saml.spi.SpringSecuritySaml;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.text.ParseException;

@Configuration
public class BeanConfig extends SamlServiceProviderServerBeanConfiguration {

    private AppConfig appConfiguration;
    private UserRepository userRepository;
    private String issuer;

    public BeanConfig(AppConfig config, UserRepository userRepository,
                      @Value("${spring.security.saml2.service-provider.entity-id}") String issuer) {
        this.appConfiguration = config;
        this.userRepository = userRepository;
        this.issuer = issuer;
    }

    @Override
    protected SamlServerConfiguration getDefaultHostSamlServerConfiguration() {
        return appConfiguration;
    }

    @Override
    @Bean
    public SpringSecuritySaml samlImplementation() {
        return super.samlImplementation();
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
    public SamlProvisioningAuthenticationManager samlProvisioningAuthenticationManager() {
        return new SamlProvisioningAuthenticationManager(this.userRepository);
    }

    @Bean
    public TokenGenerator tokenGenerator() throws ParseException, JOSEException, IOException {
        return new TokenGenerator(issuer);
    }

    @Override
    @Bean
    public Filter spAuthenticationResponseFilter() {
        SamlAuthenticationResponseFilter filter =
                SamlAuthenticationResponseFilter.class.cast(super.spAuthenticationResponseFilter());
        filter.setAuthenticationManager(this.samlProvisioningAuthenticationManager());
        return filter;

    }

}
