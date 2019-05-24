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
import oidc.repository.SequenceRepository;
import oidc.repository.SigningKeyRepository;
import oidc.repository.UserRepository;
import oidc.secure.LoggingStrictHttpFirewall;
import oidc.secure.ResourceCleaner;
import oidc.secure.TokenGenerator;
import oidc.user.SamlProvisioningAuthenticationManager;
import oidc.web.ConfigurableSamlAuthenticationRequestFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.core.io.Resource;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.provider.service.authentication.SamlAuthenticationResponseFilter;
import org.springframework.security.saml.provider.service.config.SamlServiceProviderServerBeanConfiguration;
import org.springframework.security.web.firewall.StrictHttpFirewall;

import javax.servlet.Filter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

@Configuration
@EnableScheduling
public class BeanConfig extends SamlServiceProviderServerBeanConfiguration {


    private Environment environment;
    private AppConfig appConfiguration;
    private UserRepository userRepository;
    private SigningKeyRepository signingKeyRepository;
    private SequenceRepository sequenceRepository;
    private ObjectMapper objectMapper;
    private String issuer;
    private Resource jwksKeyStorePath;
    private Resource secretKeySetPath;
    private String associatedData;

    public BeanConfig(AppConfig config,
                      UserRepository userRepository,
                      SigningKeyRepository signingKeyRepository,
                      SequenceRepository sequenceRepository,
                      ObjectMapper objectMapper,
                      Environment environment,
                      @Value("${secret_key_set_path}") Resource secretKeySetPath,
                      @Value("${associated_data}") String associatedData,
                      @Value("${spring.security.saml2.service-provider.entity-id}") String issuer,
                      @Value("${cron.node-cron-job-responsible}") boolean cronJobResponsible) {
        this.appConfiguration = config;
        this.userRepository = userRepository;
        this.signingKeyRepository = signingKeyRepository;
        this.sequenceRepository = sequenceRepository;
        this.objectMapper = objectMapper;
        this.secretKeySetPath = secretKeySetPath;
        this.associatedData = associatedData;
        this.issuer = issuer;
        this.environment = environment;
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
    public StrictHttpFirewall strictHttpFirewall() {
        return new LoggingStrictHttpFirewall();
    }

    @Override
    @Bean
    public Filter spAuthenticationResponseFilter() {
        SamlAuthenticationResponseFilter filter =
                (SamlAuthenticationResponseFilter) super.spAuthenticationResponseFilter();
        try {
            filter.setAuthenticationManager(this.samlProvisioningAuthenticationManager());
        } catch (IOException e) {
            //super has no throw clause
            throw new RuntimeException(e);
        }
        return filter;

    }
}
