package oidc.log;

import org.slf4j.MDC;
import org.slf4j.spi.MDCAdapter;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class MDCContextFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        MDCAdapter mdcAdapter = MDC.getMDCAdapter();
        mdcAdapter.clear();

        filterChain.doFilter(request, response);
    }
}
