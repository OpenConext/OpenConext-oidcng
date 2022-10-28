package oidc.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.data.mongo.JacksonMongoSessionConverter;
import org.springframework.session.data.mongo.config.annotation.web.http.EnableMongoHttpSession;
import org.springframework.session.web.context.AbstractHttpSessionApplicationInitializer;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Configuration
@EnableMongoHttpSession
public class SessionConfig extends AbstractHttpSessionApplicationInitializer {

    private static final Log LOG = LogFactory.getLog(CookieSerializer.class);

    @Bean
    CookieSerializer cookieSerializer(@Value("${secure_cookie}") boolean secureCookie) {
        DefaultCookieSerializer defaultCookieSerializer = new DefaultCookieSerializer() {
            @Override
            public List<String> readCookieValues(HttpServletRequest request) {
                Cookie[] cookies = request.getCookies();
                if (cookies != null) {
                    LOG.info("readCookieValues with cookies "+ Stream.of(cookies).map(cookie -> cookie.getValue()).collect(Collectors.toList()));
                } else {
                    LOG.info("readCookieValues with null cookies ");
                }
                List<String> cookieValues = super.readCookieValues(request);
                LOG.debug("readCookieValues: " + cookieValues);
                return cookieValues;
            }

            @Override
            public void writeCookieValue(CookieValue cookieValue) {
                LOG.info("writeCookieValue: " + (cookieValue != null ? cookieValue.getCookieValue() : "null"));
                super.writeCookieValue(cookieValue);
            }
        };
        //We don't need same-site as the load-balancer takes care of this
        defaultCookieSerializer.setSameSite(null);
        defaultCookieSerializer.setUseSecureCookie(secureCookie);
        return defaultCookieSerializer;
    }

    @Bean
    JacksonMongoSessionConverter mongoSessionConverter() {
        return new JacksonMongoSessionConverter(List.of(new AuthenticationMixinModule()));
    }


}
