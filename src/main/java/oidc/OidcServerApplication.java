package oidc;

import com.github.cloudyrock.spring.v5.EnableMongock;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.audit.AuditEventsEndpointAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.metrics.JvmMetricsAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.metrics.MetricsAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.metrics.export.simple.SimpleMetricsExportAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.metrics.web.servlet.WebMvcMetricsAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.trace.http.HttpTraceAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.web.servlet.error.ErrorMvcAutoConfiguration;

@SpringBootApplication(exclude = {WebMvcMetricsAutoConfiguration.class, HttpTraceAutoConfiguration.class,
        JvmMetricsAutoConfiguration.class, MetricsAutoConfiguration.class, SimpleMetricsExportAutoConfiguration.class,
        AuditEventsEndpointAutoConfiguration.class})
public class OidcServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(OidcServerApplication.class, args);
    }

}
