package oidc.endpoints;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class FeedbackController {

    @GetMapping(value = "feedback/no-cookies")
    public ModelAndView feedback(@RequestParam(name = "lang", required = false, defaultValue = "en") String lang) {
        String view = "en".equals(lang) ? "no_session_found" : "no_session_found_nl";
        return new ModelAndView(view, HttpStatus.OK);
    }
}
