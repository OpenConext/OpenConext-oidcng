package oidc.endpoints;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class FeedbackController {

    @GetMapping(value = "feedback/session-lost-cookies")
    public ModelAndView feedback(@RequestParam(name = "lang", required = false, defaultValue = "en") String lang) {
        String view = "en".equals(lang) ? "session_lost" : "session_lost_nl";
        return new ModelAndView(view, HttpStatus.OK);
    }
}
