package oidc.secure;

import oidc.exceptions.UnauthorizedException;
import oidc.model.AuthenticationRequest;
import oidc.repository.AuthenticationRequestRepository;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The request that is replayed after the SAML login must be identical to the request that was sent to EngineBlock
 * (and was validated by the AuthnRequestContextConsumer). Otherwise a user can alter parameters like acr_values,
 * max_age, prompt, scope, redirect_uri or the signed request object after the login has been completed.
 */
public class SavedRequestBinding {

    private static final Set<String> SPACE_DELIMITED_PARAMETERS =
        Set.of("scope", "acr_values", "response_type", "prompt", "ui_locales", "claims_locales");

    private SavedRequestBinding() {
    }

    public static void assertMatchesSavedRequest(AuthenticationRequestRepository repository,
                                                 String authenticationRequestId,
                                                 Map<String, String> incoming,
                                                 Set<String> ignoredParameters) {
        AuthenticationRequest saved = StringUtils.hasText(authenticationRequestId) ?
            repository.findById(authenticationRequestId).orElse(null) : null;
        if (saved == null || !StringUtils.hasText(saved.getOriginalRequestUrl())) {
            throw new UnauthorizedException("No saved authentication request found for the authenticated session");
        }
        Map<String, String> original = firstValues(
            UriComponentsBuilder.fromUriString(saved.getOriginalRequestUrl()).build().getQueryParams());

        Set<String> names = new HashSet<>(original.keySet());
        names.addAll(incoming.keySet());
        names.removeAll(ignoredParameters);
        for (String name : names) {
            if (!sameValue(name, original.getOrDefault(name, ""), incoming.getOrDefault(name, ""))) {
                throw new UnauthorizedException(
                    String.format("Parameter %s differs from the request the authentication was started for", name));
            }
        }
    }

    /*
     * Parameter order and percent-encoding are irrelevant (both sides are decoded). For space-delimited parameters
     * the order and the amount of whitespace between the values are irrelevant as well.
     */
    private static boolean sameValue(String name, String original, String incoming) {
        if (SPACE_DELIMITED_PARAMETERS.contains(name)) {
            return tokens(original).equals(tokens(incoming));
        }
        return original.equals(incoming);
    }

    private static Set<String> tokens(String value) {
        return Arrays.stream(value.trim().split("\\s+")).filter(StringUtils::hasText).collect(Collectors.toSet());
    }

    private static Map<String, String> firstValues(MultiValueMap<String, String> queryParams) {
        Map<String, String> result = new HashMap<>();
        queryParams.forEach((key, values) -> {
            List<String> list = values;
            String value = list == null || list.isEmpty() || list.get(0) == null ? "" : list.get(0);
            result.put(decode(key), decode(value));
        });
        return result;
    }

    private static String decode(String value) {
        //Same semantics as the servlet container, which decoded the incoming parameters
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }
}
