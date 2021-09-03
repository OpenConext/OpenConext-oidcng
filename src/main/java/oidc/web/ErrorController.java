package oidc.web;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import lombok.SneakyThrows;
import oidc.exceptions.BaseException;
import oidc.exceptions.CookiesNotSupportedException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
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
import java.net.URLEncoder;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static oidc.saml.AuthnRequestConverter.REDIRECT_URI_VALID;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

@RestController
public class ErrorController implements org.springframework.boot.web.servlet.error.ErrorController {

    private static final Log LOG = LogFactory.getLog(ErrorController.class);
    private final DefaultErrorAttributes errorAttributes;
    private RequestCache requestCache = new HttpSessionRequestCache();

    public ErrorController() {
        this.errorAttributes = new DefaultErrorAttributes();
    }

    @SneakyThrows
    @RequestMapping("${server.error.path:${error.path:/error}}")
    public Object error(HttpServletRequest request) {
        ServletWebRequest webRequest = new ServletWebRequest(request);

        Map<String, Object> result = errorAttributes.getErrorAttributes(webRequest, ErrorAttributeOptions.defaults());

        Throwable error = errorAttributes.getError(webRequest);
        if (error instanceof CookiesNotSupportedException) {
            return new ModelAndView("no_session_found", HttpStatus.OK);
        }
        if (error != null && error.getCause() != null) {
            error = error.getCause();
        }
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
        Object redirectUriValid = request.getAttribute(REDIRECT_URI_VALID);
        String redirectUri = request.getParameter("redirect_uri");
        Map<String, String[]> parameterMap = request.getParameterMap();

        SavedRequest savedRequest = requestCache.getRequest(request, null);
        boolean redirect = false;

        if (savedRequest == null) {
            LOG.warn("No saved request found. Check the cookie flow");
        }

        if (savedRequest instanceof DefaultSavedRequest) {
            parameterMap = savedRequest.getParameterMap();
            String requestURI = ((DefaultSavedRequest) savedRequest).getRequestURI();
            String[] redirectUris = parameterMap.get("redirect_uri");
            if (requestURI != null && requestURI.contains("authorize") && redirectUris != null) {
                redirectUri = redirectUris[0];
                redirect = true;
            }
        }

        if (redirectUriValid != null && (boolean) redirectUriValid &&
                (statusCode.is3xxRedirection() || redirect || StringUtils.hasText(redirectUri))) {
            return redirectErrorResponse(parameterMap, result, error, redirectUri);
        }
        return new ResponseEntity<>(result, statusCode);
    }

    private String errorCode(Throwable error) {
        if (error == null) {
            return "unknown_exception";
        }
        if (error instanceof BaseException) {
            return ((BaseException) error).getErrorCode();
        }
        if (error instanceof ParseException) {
            return "invalid_request";
        }
        if (error instanceof Saml2AuthenticationException) {
            return "access_denied";
        }
        return error.getMessage();
    }

    private String errorMessage(Throwable error) throws UnsupportedEncodingException {
        String errorMsg = error != null ? error.getMessage() : "Unknown exception occurred";
        if (error instanceof Saml2AuthenticationException) {
            //Remove this after the 5.5 release of Spring Security
            errorMsg = "The requesting service has indicated that the authenticated user is required to have validated attributes. Your institution has not provided this.";
        }
        return URLEncoder.encode(errorMsg.replaceAll("\"", ""), "UTF-8");
    }

    private Object redirectErrorResponse(Map<String, String[]> parameterMap, Map<String, Object> result, Throwable error, String redirectUri) throws UnsupportedEncodingException {
        String url = URLDecoder.decode(redirectUri, "UTF-8");

        String responseType = defaultValue(parameterMap, "response_type", "code");
        String responseMode = defaultValue(parameterMap, "response_mode", "code".equals(responseType) ? "query" : "fragment");

        String errorCode = errorCode(error);
        String errorMessage = errorMessage(error);
        String state = defaultValue(parameterMap, "state", null);

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
        return new ResponseEntity<>(result, headers, HttpStatus.FOUND);
    }

    private String defaultValue(Map<String, String[]> parameterMap, String key, String defaultValue) {
        String[] value = parameterMap.get(key);
        return value != null && value.length > 0 ? value[0] : defaultValue;
    }

}
