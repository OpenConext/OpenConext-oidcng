package oidc.web;

import com.nimbusds.jose.JOSEException;
import lombok.SneakyThrows;
import oidc.exceptions.BaseException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.autoconfigure.web.ErrorProperties;
import org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

@RestController
public class ErrorController implements org.springframework.boot.web.servlet.error.ErrorController {

    private static final Log LOG = LogFactory.getLog(ErrorController.class);
    private final DefaultErrorAttributes errorAttributes;

    public ErrorController() {
        this.errorAttributes = new DefaultErrorAttributes();
    }

    @SneakyThrows
    @RequestMapping("${server.error.path:${error.path:/error}}")
    public Object error(HttpServletRequest request) {
        ServletWebRequest webRequest = new ServletWebRequest(request);

        Map<String, Object> result = errorAttributes.getErrorAttributes(webRequest, ErrorAttributeOptions.defaults());

        Throwable error = errorAttributes.getError(webRequest);
        boolean status = result.containsKey("status") && !result.get("status").equals(999) && !result.get("status").equals(500);
        HttpStatus statusCode = status ? HttpStatus.resolve((Integer) result.get("status")) : BAD_REQUEST;
        if (error != null) {
            String message = error.getMessage();
            // Not be considered an error that we want to report
            if (!"AccessToken not found".equals(message)) {
                LOG.error("Error has occurred", error);
            }

            result.put("error_description", message);
            result.put("message", message);
            ResponseStatus annotation = AnnotationUtils.getAnnotation(error.getClass(), ResponseStatus.class);
            statusCode = annotation != null ? annotation.value() : statusCode;

            if (error instanceof JOSEException ||
                    (error instanceof EmptyResultDataAccessException &&
                            result.getOrDefault("path", "/oidc/token").toString().contains("token"))) {
                return new ResponseEntity<>(Collections.singletonMap("error", "invalid_grant"), BAD_REQUEST);
            }
        }
        result.put("error", errorCode(error));
        result.put("status", statusCode.value());

        //https://openid.net/specs/openid-connect-core-1_0.html#AuthError
        Object redirectUriValid = request.getAttribute(ConfigurableSamlAuthenticationRequestFilter.REDIRECT_URI_VALID);
        String redirectUri = request.getParameter("redirect_uri");

        if (redirectUriValid != null && (boolean) redirectUriValid && (statusCode.is3xxRedirection() || ((String) result.getOrDefault("path", "")).contains("authorize"))
                && StringUtils.hasText(redirectUri)) {

            return redirectErrorResponse(request, result, error, redirectUri);
        }
        return new ResponseEntity<>(result, statusCode);
    }

    private String errorCode(Throwable error) {
        return error == null ? "unknown_exception" : error instanceof BaseException ?
                ((BaseException) error).getErrorCode() : error.getMessage();
    }

    private String errorMessage(Throwable error) {
        return error == null ? "Unknown exception occurred" : error.getMessage();
    }

    private Object redirectErrorResponse(HttpServletRequest request, Map<String, Object> result, Throwable error, String redirectUri) throws UnsupportedEncodingException {
        String url = URLDecoder.decode(redirectUri, "UTF-8");

        String responseType = defaultValue(request, "response_type", "code");
        String responseMode = defaultValue(request, "response_mode", "code".equals(responseType) ? "query" : "fragment");

        String errorCode = errorCode(error);
        String errorMessage = errorMessage(error);
        String state = defaultValue(request, "state", null);

        UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(url);

        switch (responseMode) {
            case "query": {
                uriComponentsBuilder
                        .queryParam("error", errorCode)
                        .queryParam("error_description", errorMessage);
                if (StringUtils.hasText(state)) {
                    uriComponentsBuilder.queryParam("state", state);
                }

                break;
            }
            case "fragment": {
                String fragment = String.format("error=%s&error_description=%s", errorCode, errorMessage);
                if (StringUtils.hasText(state)) {
                    fragment = fragment.concat(String.format("&state=%s", state));
                }
                uriComponentsBuilder.fragment(fragment);
                break;
            }
            case "form_post": {
                Map<String, String> body = new HashMap<>();
                body.put("redirect_uri", url);
                body.put("error", errorCode);
                body.put("error_description", errorMessage);
                if (StringUtils.hasText(state)) {
                    body.put("state", state);
                }
                LOG.debug("Post form to " + url);

                return new ModelAndView("form_post", body);
            }
            default://nope
        }
        URI uri = uriComponentsBuilder.build().toUri();

        LOG.debug("Redirect to " + uri);

        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(uri);
        HttpStatus statusCode = HttpStatus.FOUND;
        return new ResponseEntity<>(result, headers, statusCode);
    }

    private String defaultValue(HttpServletRequest request, String key, String defaultValue) {
        String value = request.getParameter(key);
        return StringUtils.hasText(value) ? value : defaultValue;
    }

    @Override
    public String getErrorPath() {
        return null;
    }
}
