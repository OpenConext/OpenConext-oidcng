package oidc.web;

//@RestControllerAdvice
public class CustomErrorControllerOld {

//    private static final Log LOG = LogFactory.getLog(CustomErrorController.class);
//    private final DefaultErrorAttributes errorAttributes;
//    private final RequestCache requestCache = new HttpSessionRequestCache();
//    private final List<Class<? extends Exception>> exceptionsToExclude = List.of(
//            RedirectMismatchException.class,
//            UnauthorizedException.class,
//            CodeVerifierMissingException.class,
//            UnsupportedPromptValueException.class,
//            TokenAlreadyUsedException.class,
//            UnknownClientException.class,
//            UnknownCodeException.class
//    );
//
//    public CustomErrorController() {
//        this.errorAttributes = new DefaultErrorAttributes();
//    }
//
//    @ExceptionHandler({Exception.class})
//    public Object handleError(Exception ex, HttpServletRequest request) {
//        return handleError(request);
//    }
//
//    @SneakyThrows
//    private Object handleError(HttpServletRequest request) {
//        ServletWebRequest webRequest = new ServletWebRequest(request);
//
//        Map<String, Object> result = errorAttributes.getErrorAttributes(webRequest, ErrorAttributeOptions.defaults());
//
//        Throwable error = errorAttributes.getError(webRequest);
//        if (error instanceof CookiesNotSupportedException) {
//            return new ModelAndView("no_session_found", HttpStatus.OK);
//        }
//        if (error != null && error.getCause() != null) {
//            error = error.getCause();
//        }
//        boolean status = result.containsKey("status") && !result.get("status").equals(999) && !result.get("status").equals(500);
//        HttpStatus statusCode;
//        if (error instanceof NoResourceFoundException) {
//            statusCode = HttpStatus.NOT_FOUND;
//        } else {
//            statusCode = status ? HttpStatus.resolve((Integer) result.get("status")) : BAD_REQUEST;
//        }
//
//        if (error != null) {
//            String message = error.getMessage();
//            // Not be considered an error that we want to report
//            if (!"AccessToken not found".equals(message)) {
//                if (this.exceptionsToExclude.contains(error.getClass())) {
//                    LOG.error("Error has occurred: " + error);
//                } else {
//                    LOG.error("Error has occurred", error);
//                }
//            }
//
//            result.put("error_description", message);
//            result.put("message", message);
//            ResponseStatus annotation = AnnotationUtils.getAnnotation(error.getClass(), ResponseStatus.class);
//            statusCode = annotation != null ? annotation.value() : statusCode;
//
//            if (error instanceof JOSEException ||
//                    (error instanceof EmptyResultDataAccessException &&
//                            result.getOrDefault("path", "/oidc/token").toString().contains("token"))) {
//                return new ResponseEntity<>(Collections.singletonMap("error", "invalid_grant"), BAD_REQUEST);
//            }
//        }
//        result.put("error", errorCode(error));
//        result.put("status", statusCode.value());
//
//        //https://openid.net/specs/openid-connect-core-1_0.html#AuthError
//        Object redirectUriValid = request.getAttribute(REDIRECT_URI_VALID);
//        String redirectUri = request.getParameter("redirect_uri");
//        Map<String, String[]> parameterMap = request.getParameterMap();
//
//        SavedRequest savedRequest = requestCache.getRequest(request, null);
//        boolean redirect = false;
//
//        boolean isDeviceFlow = error instanceof DeviceFlowException;
//        if (error instanceof ContextSaml2AuthenticationException) {
//            ContextSaml2AuthenticationException ctxE = (ContextSaml2AuthenticationException) error;
//            String originalRequestUrl = ctxE.getAuthenticationRequest().getOriginalRequestUrl();
//            UriComponents uriComponent = UriComponentsBuilder.fromUriString(originalRequestUrl).build();
//            redirectUri = uriComponent.getQueryParams().getFirst("redirect_uri");
//            redirect = true;
//        } else if (savedRequest == null && !isDeviceFlow) {
//            LOG.warn("No saved request found. Check the cookie flow");
//
//        }
//        if (savedRequest instanceof DefaultSavedRequest) {
//            parameterMap = savedRequest.getParameterMap();
//            String requestURI = ((DefaultSavedRequest) savedRequest).getRequestURI();
//            String[] redirectUris = parameterMap.get("redirect_uri");
//            if (requestURI != null && requestURI.contains("authorize") && redirectUris != null) {
//                redirectUri = redirectUris[0];
//                redirect = true;
//            }
//        }
//
//        if (redirectUriValid != null && (boolean) redirectUriValid &&
//                (statusCode.is3xxRedirection() || redirect || StringUtils.hasText(redirectUri))) {
//            return redirectErrorResponse(parameterMap, result, error, redirectUri, statusCode);
//        }
//        return new ResponseEntity<>(result, statusCode);
//    }
//
//    private String errorCode(Throwable error) {
//        if (error instanceof WrappingException) {
//            error = ((WrappingException) error).getOriginalException();
//        }
//        if (error == null) {
//            return "unknown_exception";
//        }
//        if (error instanceof BaseException) {
//            return ((BaseException) error).getErrorCode();
//        }
//        if (error instanceof ParseException) {
//            return "invalid_request";
//        }
//        if (error instanceof Saml2AuthenticationException) {
//            return "access_denied";
//        }
//        return error.getMessage();
//    }
//
//    private String errorMessage(Throwable error) throws UnsupportedEncodingException {
//        String errorMsg = error != null ? error.getMessage() : "Unknown exception occurred";
//        return URLEncoder.encode(errorMsg.replaceAll("\"", ""), StandardCharsets.UTF_8);
//    }
//
//    private Object redirectErrorResponse(Map<String, String[]> parameterMap,
//                                         Map<String, Object> result,
//                                         Throwable error,
//                                         String redirectUri,
//                                         HttpStatus statusCode) throws UnsupportedEncodingException {
//        String url = URLDecoder.decode(redirectUri, StandardCharsets.UTF_8);
//
//        String responseType = defaultValue(parameterMap, "response_type", "code");
//        String responseMode = defaultValue(parameterMap, "response_mode", "code".equals(responseType) ? "query" : "fragment");
//
//        String errorCode = errorCode(error);
//        String errorMessage = errorMessage(error);
//        String state = defaultValue(parameterMap, "state", null);
//
//        UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(url);
//
//        switch (responseMode) {
//            case "query": {
//                uriComponentsBuilder
//                        .queryParam("error", errorCode)
//                        .queryParam("error_description", errorMessage);
//                if (StringUtils.hasText(state)) {
//                    uriComponentsBuilder.queryParam("state", state);
//                }
//
//                break;
//            }
//            case "fragment": {
//                String fragment = String.format("error=%s&error_description=%s", errorCode, errorMessage);
//                if (StringUtils.hasText(state)) {
//                    fragment = fragment.concat(String.format("&state=%s", state));
//                }
//                uriComponentsBuilder.fragment(fragment);
//                break;
//            }
//            case "form_post": {
//                Map<String, String> body = new HashMap<>();
//                body.put("redirect_uri", url);
//                body.put("error", errorCode);
//                body.put("error_description", errorMessage);
//                if (StringUtils.hasText(state)) {
//                    body.put("state", state);
//                }
//                LOG.debug("Post form to " + url);
//
//                return new ModelAndView("form_post", body, statusCode);
//            }
//            default://nope
//        }
//        URI uri = uriComponentsBuilder.build().toUri();
//
//        LOG.debug("Redirect to " + uri);
//
//        HttpHeaders headers = new HttpHeaders();
//        headers.setLocation(uri);
//        return new ResponseEntity<>(result, headers, HttpStatus.FOUND);
//    }
//
//    private String defaultValue(Map<String, String[]> parameterMap, String key, String defaultValue) {
//        String[] value = parameterMap.get(key);
//        return value != null && value.length > 0 ? value[0] : defaultValue;
//    }

}
