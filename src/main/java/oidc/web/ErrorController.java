package oidc.web;

import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.util.Map;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

@RestController
public class ErrorController implements org.springframework.boot.web.servlet.error.ErrorController {

    private ErrorAttributes errorAttributes;

    public ErrorController(ErrorAttributes errorAttributes) {
        this.errorAttributes = errorAttributes;
    }

    @Override
    public String getErrorPath() {
        return "/error";
    }

    @RequestMapping("/error")
    public ResponseEntity error(HttpServletRequest request) throws UnsupportedEncodingException, URISyntaxException {
        ServletWebRequest webRequest = new ServletWebRequest(request);
        Map<String, Object> result = this.errorAttributes.getErrorAttributes(webRequest, false);
        Throwable error = this.errorAttributes.getError(webRequest);
        HttpStatus statusCode = result.containsKey("status") ? HttpStatus.valueOf((Integer) result.get("status")) : BAD_REQUEST;
        if (error != null) {
            result.put("details", error.getMessage());
        }
        if (error != null) {
            ResponseStatus annotation = AnnotationUtils.getAnnotation(error.getClass(), ResponseStatus.class);
            statusCode = annotation != null ? annotation.value() : statusCode;
        }
        HttpHeaders headers = new HttpHeaders();
        String redirectUri = request.getParameter("redirect_uri");
        if ((statusCode.is3xxRedirection() || ((String) result.getOrDefault("path", "")).contains("authorize"))
                && StringUtils.hasText(redirectUri)) {
            headers.setLocation(new URI(URLDecoder.decode(redirectUri, Charset.defaultCharset().toString())));
            statusCode = HttpStatus.FOUND;
        }
        return new ResponseEntity<>(result, headers, statusCode);
    }

}
