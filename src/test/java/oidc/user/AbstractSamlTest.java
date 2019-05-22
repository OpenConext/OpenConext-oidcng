package oidc.user;

import oidc.TestUtils;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.time.Clock;
import java.util.Collections;

abstract class AbstractSamlTest implements TestUtils {

    private OpenSamlImplementation openSamlImplementation = new OpenSamlImplementation(Clock.systemDefaultZone());

    {
        ReflectionTestUtils.invokeMethod(openSamlImplementation, "bootstrap");
    }

    <T> T resolveXml(Class<T> clazz, String path) throws IOException {
        byte[] xml = StreamUtils.copyToByteArray(
                new ClassPathResource(path).getInputStream());
        return clazz.cast(openSamlImplementation.resolve(xml, Collections.emptyList(), Collections.emptyList()));
    }

}
