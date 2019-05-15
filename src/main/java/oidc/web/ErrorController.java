package oidc.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.util.Map;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

@RestController
public class ErrorController implements org.springframework.boot.web.servlet.error.ErrorController {

    private static final Log LOG = LogFactory.getLog(ErrorController.class);

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

        LOG.error("Error has occurred: " + result);

        Throwable error = this.errorAttributes.getError(webRequest);
        boolean status = result.containsKey("status") && !result.get("status").equals(999);
        HttpStatus statusCode = status ? HttpStatus.resolve((Integer) result.get("status")) : BAD_REQUEST;
        if (error != null) {
            LOG.error("Exception in /error: ", error);

            result.put("details", error.getMessage());
            ResponseStatus annotation = AnnotationUtils.getAnnotation(error.getClass(), ResponseStatus.class);
            statusCode = annotation != null ? annotation.value() : statusCode;
        }
        HttpHeaders headers = new HttpHeaders();
        String redirectUri = request.getParameter("redirect_uri");
        if ((statusCode.is3xxRedirection() || ((String) result.getOrDefault("path", "")).contains("authorize"))
                && StringUtils.hasText(redirectUri)) {
            String url = URLDecoder.decode(redirectUri, Charset.defaultCharset().toString());
            URI uri = UriComponentsBuilder.fromUriString(url)
                    .queryParam("error", "invalid_request")
                    .queryParam("error_description", error != null ? error.getMessage() : "unknown_exception")
                    .queryParam("state", request.getParameter("state"))
                    .build()
                    .toUri();

            LOG.info("Redirection after error to " + uri);

            headers.setLocation(uri);
            statusCode = HttpStatus.FOUND;
        }
        return new ResponseEntity<>(result, headers, statusCode);
    }

}
