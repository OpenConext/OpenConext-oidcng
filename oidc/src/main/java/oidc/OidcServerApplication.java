package oidc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.audit.AuditEventsEndpointAutoConfiguration;
import org.springframework.boot.micrometer.metrics.autoconfigure.jvm.JvmMetricsAutoConfiguration;
import org.springframework.boot.micrometer.metrics.autoconfigure.MetricsAutoConfiguration;
import org.springframework.boot.micrometer.metrics.autoconfigure.export.simple.SimpleMetricsExportAutoConfiguration;
import org.springframework.boot.micrometer.observation.autoconfigure.ObservationAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication(exclude = {ObservationAutoConfiguration.class,
        JvmMetricsAutoConfiguration.class, MetricsAutoConfiguration.class, SimpleMetricsExportAutoConfiguration.class,
        AuditEventsEndpointAutoConfiguration.class})
@EnableScheduling
public class OidcServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(OidcServerApplication.class, args);
    }

}
