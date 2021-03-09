package oidc.endpoints;

import oidc.model.OpenIDClient;
import oidc.repository.OpenIDClientRepository;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

//@Controller
public class ConsentEndpoint {

    private final OpenIDClientRepository openIDClientRepository;

    public ConsentEndpoint(OpenIDClientRepository openIDClientRepository) {
        this.openIDClientRepository = openIDClientRepository;
    }

    @GetMapping("/consent")
    public ModelAndView consent() {
        OpenIDClient rs = openIDClientRepository.findByClientId("mock-sp");
        OpenIDClient client = openIDClientRepository.findByClientId("playground_client");
        Map<String, Object> body = new HashMap<>();
        body.put("resourceServers", Arrays.asList(rs));
        body.put("client", client);
        body.put("scopes", rs.getScopes());
        Locale locale = LocaleContextHolder.getLocale();
        body.put("lang", locale.getLanguage());
        return new ModelAndView("consent", body);
    }

}
