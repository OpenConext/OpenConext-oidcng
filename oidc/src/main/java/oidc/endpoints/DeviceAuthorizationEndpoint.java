package oidc.endpoints;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.device.DeviceAuthorizationRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.JakartaServletUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import oidc.crypto.SimpleEncryptionHandler;
import oidc.exceptions.InvalidGrantException;
import oidc.exceptions.UnknownClientException;
import oidc.model.DeviceAuthorization;
import oidc.model.DeviceAuthorizationStatus;
import oidc.model.OpenIDClient;
import oidc.model.User;
import oidc.qr.QRGenerator;
import oidc.repository.DeviceAuthorizationRepository;
import oidc.repository.OpenIDClientRepository;
import oidc.user.OidcSamlAuthentication;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static com.nimbusds.oauth2.sdk.GrantType.DEVICE_CODE;
import static java.nio.charset.Charset.defaultCharset;
import static oidc.endpoints.AuthorizationEndpoint.validateScopes;

@RestController
@ConditionalOnExpression("${features.oidcng_device_flow:false}")
public class DeviceAuthorizationEndpoint implements OidcEndpoint {

    private static final Log LOG = LogFactory.getLog(DeviceAuthorizationEndpoint.class);

    private static final char[] USER_CODE_CODEX = "BCDFGHJKLMNPQRSTVWXZ".toCharArray();

    private static final int RATE_LIMIT = 3;

    private static final Random random = new SecureRandom();

    private final DeviceAuthorizationRepository deviceAuthorizationRepository;
    private final OpenIDClientRepository openIDClientRepository;
    private final String verificationUrl;
    private final String environment;

    public DeviceAuthorizationEndpoint(DeviceAuthorizationRepository deviceAuthorizationRepository,
                                       OpenIDClientRepository openIDClientRepository,
                                       @Value("${device_verification_url}") String verificationUrl,
                                       @Value("${environment}") String environment) {
        this.deviceAuthorizationRepository = deviceAuthorizationRepository;
        this.openIDClientRepository = openIDClientRepository;
        this.verificationUrl = verificationUrl;
        this.environment = environment;
    }

    @PostMapping(value = "oidc/device_authorization", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public ResponseEntity<Map<String, Object>> deviceAuthorization(HttpServletRequest request) throws IOException, ParseException {
        HTTPRequest httpRequest = JakartaServletUtils.createHTTPRequest(request);
        DeviceAuthorizationRequest deviceAuthorizationRequest = DeviceAuthorizationRequest.parse(httpRequest);
        // Mandatory client ID as we don't allow for authenticated requests for devices that most likely can't hide secrets
        String clientId = deviceAuthorizationRequest.getClientID().getValue();
        OpenIDClient client = openIDClientRepository.findOptionalByClientId(clientId).orElseThrow(() -> new UnknownClientException(clientId));
        if (!client.getGrants().contains(DEVICE_CODE.getValue())) {
            throw new InvalidGrantException(String.format("Missing grant: %s for clientId: %s", DEVICE_CODE.getValue(), clientId));
        }
        List<String> scopes = validateScopes(openIDClientRepository, deviceAuthorizationRequest.getScope(), client);

        LOG.debug(String.format("Device Authorization flow for clientId: %s, scopes: %s", clientId, scopes));
        //Do not bother with difficult hashes, UUID will do
        String deviceCode = UUID.randomUUID().toString();
        //Easy to type, low entropy, but in combination with the deviceCode required for the actual access code this is not an issue
        String userCode = generateUserCode();
        DeviceAuthorization deviceAuthorization = new DeviceAuthorization(
                null,//generated by mongoDB
                clientId,
                deviceCode,
                userCode.replaceAll("-", ""),
                scopes,
                UUID.randomUUID().toString(),
                getCustomParam(deviceAuthorizationRequest, "prompt"),
                getCustomParam(deviceAuthorizationRequest, "acr_values"),
                getCustomParam(deviceAuthorizationRequest, "login_hint"),
                DeviceAuthorizationStatus.authorization_pending,
                null,
                null,
                Instant.now().plus(15, ChronoUnit.MINUTES)
        );
        deviceAuthorizationRepository.save(deviceAuthorization);

        String hint = URLEncoder.encode(SimpleEncryptionHandler.encrypt(userCode), Charset.defaultCharset());
        String verificationUrlWithHint = String.format("%s?hint=%s", verificationUrl, hint);

        Map<String, Object> results = Map.of(
                "device_code", deviceCode,
                "user_code", userCode,
                "verification_uri", verificationUrlWithHint,
                "verification_uri_complete", String.format("%s?user_code=%s", verificationUrl, userCode),
                "qr_code", QRGenerator.qrCode(verificationUrlWithHint).getImage(),
                //The lifetime in seconds of the "device_code" and "user_code"
                "expires_in", 60 * 15,
                //The minimum amount of time in seconds that the client SHOULD wait between polling requests to the token endpoint
                "interval", 1);

        return ResponseEntity.ok(results);
    }

    @GetMapping(value = "oidc/verify")
    public ModelAndView verification(@RequestParam(value = "user_code", required = false) String userCode,
                                     @RequestParam(value = "hint", required = false) String hint,
                                     @RequestParam(value = "error", required = false, defaultValue = "false") String error,
                                     HttpServletRequest request) {
        AtomicReference<String> userCodeRef = new AtomicReference<>(userCode);
        Map<String, Object> model = new HashMap<>();
        if (StringUtils.hasText(hint)) {
            userCodeRef.set(SimpleEncryptionHandler.decrypt(hint));
        }
        if (StringUtils.hasText(userCodeRef.get())) {
            //When the code checks out, then retrieve the client for displaying purposes
            findByUserCode(userCodeRef.get())
                    .flatMap(deviceAuthorization -> openIDClientRepository.findOptionalByClientId(deviceAuthorization.getClientId()))
                    //Check the very strange use-case for the client not existing anymore
                    .ifPresent(openIDClient -> {
                        model.put("client", openIDClient);
                        model.put("userCode", StringUtils.hasText(userCode) ? userCodeRef.get() : null);
                        model.put("completeURI", StringUtils.hasText(userCode));
                    });
        }
        model.putIfAbsent("completeURI", false);

        addStandardModelAttributes(model);

        boolean hasError = Boolean.parseBoolean(error);
        if (hasError) {
            HttpSession session = request.getSession(true);
            Integer attempts = (Integer) session.getAttribute("attempts");
            attempts = attempts == null ? 1 : attempts + 1;
            session.setAttribute("attempts", attempts);
            if (attempts >= RATE_LIMIT) {
                model.put("rateLimitExceeded", true);
            } else {
                model.put("attemptsLeft", RATE_LIMIT - attempts);
            }
        }
        model.put("error", hasError);
        model.putIfAbsent("rateLimitExceeded", false);
        return new ModelAndView("verify", model);
    }

    @PostMapping(value = "oidc/verify")
    public ModelAndView postVerify(@RequestParam Map<String, String> body, HttpServletRequest request) {
        //Check if the code is ok, otherwise return error
        String userCode = body.getOrDefault("userCode", body.get("userCodeComplete"));
        ModelAndView modelAndView = findByUserCode(userCode)
                //avoid replay's
                .filter(deviceAuthorization -> deviceAuthorization.getStatus().equals(DeviceAuthorizationStatus.authorization_pending))
                .map(deviceAuthorization -> {
                    //We do not provide SSO as does EB not - up to the identity provider
                    logout(request);
                    return new ModelAndView(new RedirectView(deviceAuthorizeURL(deviceAuthorization), true));
                })
                .orElseGet(() -> this.verification(null, null, "true", request));
        return modelAndView;
    }

    @GetMapping("/oidc/device_authorize")
    public ModelAndView deviceAuthorize(@RequestParam(value = "state") String state,
                                        @RequestParam(value = "user_code") String userCode,
                                        Authentication authentication) {
        LOG.debug(String.format("/oidc/device_authorize %s %s", authentication.getDetails(), userCode));
        //If the state (e.g. userCode) corresponds with a DeviceAuthentication then mark this as succes and inform the user
        Map<String, Object> model = new HashMap<>();
        Optional<DeviceAuthorization> optionalDeviceAuthorization = findByUserCode(userCode);
        AtomicBoolean stateMatches = new AtomicBoolean(false);
        optionalDeviceAuthorization.ifPresent(deviceAuthorization -> {
            stateMatches.set(state.equals(deviceAuthorization.getState()));
            openIDClientRepository.findOptionalByClientId(deviceAuthorization.getClientId())
                    .ifPresent(openIDClient -> model.put("client", openIDClient));
            OidcSamlAuthentication oidcSamlAuthentication = (OidcSamlAuthentication) authentication;
            User user = oidcSamlAuthentication.getUser();
            model.put("user", user);
            deviceAuthorization.setStatus(DeviceAuthorizationStatus.success);
            deviceAuthorization.setUserSub(user.getSub());
            deviceAuthorizationRepository.save(deviceAuthorization);
        });
        addStandardModelAttributes(model);
        return new ModelAndView(optionalDeviceAuthorization.isPresent() && stateMatches.get() ? "device_continue" : "device_error", model);
    }

    //https://datatracker.ietf.org/doc/html/rfc8628#section-6.1
    protected String generateUserCode() {
        byte[] verifierBytes = new byte[8];
        random.nextBytes(verifierBytes);
        char[] chars = new char[verifierBytes.length];
        for (int i = 0; i < verifierBytes.length; i++) {
            chars[i] = USER_CODE_CODEX[random.nextInt(USER_CODE_CODEX.length)];
        }
        String userCode = new String(chars);
        return userCode.substring(0, 4) + "-" + userCode.substring(4);
    }

    private Optional<DeviceAuthorization> findByUserCode(String userCode) {
        userCode = userCode.toUpperCase().replaceAll("-", "");
        return deviceAuthorizationRepository.findByUserCode(userCode);
    }

    private void addStandardModelAttributes(Map<String, Object> model) {
        Locale locale = LocaleContextHolder.getLocale();
        model.put("lang", locale.getLanguage());
        model.put("environment", environment);
    }

    private String getCustomParam(DeviceAuthorizationRequest deviceAuthorizationRequest, String key) {
        List<String> values = deviceAuthorizationRequest.getCustomParameters().get(key);
        return CollectionUtils.isEmpty(values) ? null : values.get(0);
    }

    private String deviceAuthorizeURL(DeviceAuthorization deviceAuthorization) {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("client_id", deviceAuthorization.getClientId());
        parameters.put("user_code", deviceAuthorization.getUserCode());
        parameters.put("prompt", deviceAuthorization.getPrompt());
        parameters.put("acr_values", deviceAuthorization.getAcrValues());
        parameters.put("login_hint", deviceAuthorization.getLoginHint());
        parameters.put("state", deviceAuthorization.getState());
        String queryParams = parameters.entrySet().stream()
                .filter(entry -> StringUtils.hasText(entry.getValue()))
                .map(entry -> entry.getKey() + "=" + URLEncoder.encode(entry.getValue(), defaultCharset()))
                .reduce((p1, p2) -> p1 + "&" + p2)
                .orElse("");
        return String.format("/oidc/device_authorize?%s", queryParams);
    }

}
