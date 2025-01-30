package oidc.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;
import java.util.List;

public class OidcCorsConfigurationSource implements CorsConfigurationSource {

    private final CorsConfiguration corsConfiguration;

    public OidcCorsConfigurationSource() {
        List<String> allAllowed = Collections.singletonList(CorsConfiguration.ALL);

        corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOriginPatterns(allAllowed);
        corsConfiguration.setAllowedMethods(allAllowed);
        corsConfiguration.setAllowedHeaders(allAllowed);
        corsConfiguration.setMaxAge(1800L);
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.setExposedHeaders(allAllowed);
    }

    @Override
    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
        return corsConfiguration;
    }
}
