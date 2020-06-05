package oidc.config;

import ch.qos.logback.classic.filter.ThresholdFilter;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.classic.spi.ThrowableProxy;
import ch.qos.logback.core.spi.FilterReply;

import java.util.Arrays;
import java.util.List;

public class CustomThresholdFilter extends ThresholdFilter {

    private List<Class> ignoreClasses = Arrays.asList(
            com.nimbusds.oauth2.sdk.ParseException.class,
            org.springframework.security.authentication.BadCredentialsException.class,
            oidc.exceptions.RedirectMismatchException.class,
            org.springframework.dao.EmptyResultDataAccessException.class,
            java.lang.IllegalArgumentException.class
    );

    @Override
    public FilterReply decide(ILoggingEvent event) {
        FilterReply decide = super.decide(event);
        if (decide.equals(FilterReply.NEUTRAL)) {
            IThrowableProxy throwableProxy = event.getThrowableProxy();
            if (throwableProxy == null) {
                return FilterReply.NEUTRAL;
            }

            if (!(throwableProxy instanceof ThrowableProxy)) {
                return FilterReply.NEUTRAL;
            }

            ThrowableProxy throwableProxyImpl = (ThrowableProxy) throwableProxy;
            Throwable throwable = throwableProxyImpl.getThrowable();
            if (ignoreClasses.contains(throwable.getClass())) {
                return FilterReply.DENY;
            }
        }
        return decide;
    }
}
