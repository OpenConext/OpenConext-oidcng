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
import lombok.SneakyThrows;
import oidc.repository.AuthenticationRequestRepository;
import oidc.repository.OpenIDClientRepository;
import oidc.repository.UserConsentRepository;
import oidc.repository.UserRepository;
import oidc.secure.CustomValidator;
import oidc.secure.LoggingStrictHttpFirewall;
import oidc.user.SamlProvisioningAuthenticationManager;
import oidc.web.ConcurrentSavedRequestAwareAuthenticationSuccessHandler;
import oidc.web.ConfigurableSamlAuthenticationRequestFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.provider.service.authentication.SamlAuthenticationResponseFilter;
import org.springframework.security.saml.provider.service.config.SamlServiceProviderServerBeanConfiguration;
import org.springframework.security.saml.spi.DefaultValidator;
import org.springframework.security.saml.spi.SpringSecuritySaml;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.util.ReflectionUtils;

import javax.servlet.Filter;
import java.io.IOException;
import java.lang.reflect.Field;

@Configuration
@EnableScheduling
public class BeanConfig extends SamlServiceProviderServerBeanConfiguration {


    private AppConfig appConfiguration;
    private UserRepository userRepository;
    private AuthenticationRequestRepository authenticationRequestRepository;
    private OpenIDClientRepository openIDClientRepository;
    private ObjectMapper objectMapper;
    private Resource oidcSamlMapping;

    public BeanConfig(AppConfig config,
                      UserRepository userRepository,
                      AuthenticationRequestRepository authenticationRequestRepository,
                      OpenIDClientRepository openIDClientRepository,
                      ObjectMapper objectMapper,
                      @Value("${oidc_saml_mapping_path}") Resource oidcSamlMapping) {
        this.appConfiguration = config;
        this.userRepository = userRepository;
        this.openIDClientRepository = openIDClientRepository;
        this.authenticationRequestRepository = authenticationRequestRepository;
        this.objectMapper = objectMapper;
        this.oidcSamlMapping = oidcSamlMapping;
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
    @SneakyThrows
    public SamlValidator samlValidator() {
        //IdP determines session expiration not we
        DefaultValidator defaultValidator = (DefaultValidator) super.samlValidator();
        Field field = defaultValidator.getClass().getDeclaredField("implementation");
        //Hack, but the DefaultValidator is not easy to extend
        ReflectionUtils.makeAccessible(field);
        SpringSecuritySaml springSecuritySaml = (SpringSecuritySaml) ReflectionUtils.getField(field, defaultValidator);
        CustomValidator customValidator = new CustomValidator(springSecuritySaml);
        customValidator.setResponseSkewTimeMillis(1000 * 60 * 10);
        return customValidator;
    }

    @Override
    @Bean
    public Filter spAuthenticationRequestFilter() {
        SamlProviderProvisioning<ServiceProviderService> provisioning = getSamlProvisioning();
        SamlRequestMatcher requestMatcher = new SamlRequestMatcher(provisioning, "authorize", false);
        return new ConfigurableSamlAuthenticationRequestFilter(provisioning, requestMatcher,
                authenticationRequestRepository, openIDClientRepository, objectMapper);
    }

    @Bean
    public SamlProvisioningAuthenticationManager samlProvisioningAuthenticationManager() throws IOException {
        return new SamlProvisioningAuthenticationManager(this.userRepository, this.objectMapper, oidcSamlMapping);
    }

    @Bean
    public StrictHttpFirewall strictHttpFirewall() {
        return new LoggingStrictHttpFirewall();
    }

    @Override
    @Bean
    @SneakyThrows
    public Filter spAuthenticationResponseFilter() {
        SamlAuthenticationResponseFilter filter =
                (SamlAuthenticationResponseFilter) super.spAuthenticationResponseFilter();
        filter.setAuthenticationManager(this.samlProvisioningAuthenticationManager());
        filter.setAuthenticationSuccessHandler(new ConcurrentSavedRequestAwareAuthenticationSuccessHandler(this.authenticationRequestRepository));
        return filter;

    }
}
