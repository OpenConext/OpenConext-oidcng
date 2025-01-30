package oidc.secure;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.web.firewall.FirewalledRequest;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.security.web.firewall.StrictHttpFirewall;

import jakarta.servlet.http.HttpServletRequest;

public class LoggingStrictHttpFirewall extends StrictHttpFirewall {

    private static final Log LOG = LogFactory.getLog(LoggingStrictHttpFirewall.class);

    @Override
    public FirewalledRequest getFirewalledRequest(HttpServletRequest request) throws RequestRejectedException {
        try {
            return super.getFirewalledRequest(request);
        } catch (RequestRejectedException e) {
            LOG.info(String.format("Request rejected. URL info requestURI='%s' contextPath='%s' servletPath='%s' pathInfo='%s'",
                    request.getRequestURI(), request.getContextPath(), request.getServletPath(), request.getPathInfo()));
            throw e;
        }
    }
}
