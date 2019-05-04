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
package oidc.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class ServiceProviderController {

    private static final Log logger = LogFactory.getLog(ServiceProviderController.class);
    private SamlProviderProvisioning<ServiceProviderService> provisioning;

    @Autowired
    public void setSamlService(SamlProviderProvisioning<ServiceProviderService> provisioning) {
        this.provisioning = provisioning;
    }

    @RequestMapping(value = {"/", "/index", "/logged-in"})
    public ModelAndView home(HttpServletRequest request, Authentication authentication) {
        logger.info("You are logged in!");
        return new ModelAndView("logged-in", "user", authentication);
    }

    @PostMapping("/local/logout")
    public View logout(HttpServletRequest request,
                       HttpServletResponse response, Authentication authentication) {
        logger.info("Logging out locally");
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.logout(request, response, authentication);
        return new RedirectView("/");
    }

}
