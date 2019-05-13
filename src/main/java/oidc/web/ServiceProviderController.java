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

import oidc.model.User;
import oidc.user.OidcSamlAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;

@Controller
public class ServiceProviderController {

    @RequestMapping(value = {"/"})
    public ModelAndView home(HttpServletRequest request, Authentication authentication) {
        if (!(authentication instanceof OidcSamlAuthentication)) {
            throw new IllegalArgumentException("Root endpoint requires an OIDC SAML Authentication");
        }

        OidcSamlAuthentication oidcSamlAuthentication = (OidcSamlAuthentication) authentication;
        User user = (User) oidcSamlAuthentication.getDetails();
        return new ModelAndView("demo", "user", user);
    }

}
