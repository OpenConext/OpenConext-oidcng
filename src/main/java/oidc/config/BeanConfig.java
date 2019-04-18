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

import oidc.web.ConfigurableSamlAuthenticationRequestFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.service.config.SamlServiceProviderServerBeanConfiguration;
import org.springframework.security.saml.spi.SpringSecuritySaml;

import javax.servlet.Filter;

@Configuration
public class BeanConfig extends SamlServiceProviderServerBeanConfiguration {

    private AppConfig appConfiguration;

    public BeanConfig(AppConfig config) {
        appConfiguration = config;
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
        //TODO Replace with noopFilter
        return super.spSelectIdentityProviderFilter();
    }

    @Override
    @Bean
    public Filter spAuthenticationRequestFilter() {
        return new ConfigurableSamlAuthenticationRequestFilter(getSamlProvisioning());
    }

    @Override
    @Bean
    public Filter spAuthenticationResponseFilter() {
        //replace the authenticationFilter.setAuthenticationSuccessHandler(new SavedRequestAwareAuthenticationSuccessHandler());
        //replace the authenticationFilter.setAuthenticationManager(new SimpleAuthenticationManager()); to retrieve
        // the client-id, relay-state off the authentication
        return super.spAuthenticationResponseFilter();
    }
}
