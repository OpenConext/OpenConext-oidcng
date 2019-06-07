package oidc.user;

import oidc.TestUtils;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.time.Clock;
import java.util.Base64;
import java.util.Collections;

public interface SamlTest extends TestUtils {


    OpenSamlImplementation openSamlImplementation = OpenSamlImplementationWrapper.init();

    class OpenSamlImplementationWrapper {
        private static OpenSamlImplementation init() {
            OpenSamlImplementation openSamlImplementation = new OpenSamlImplementation(Clock.systemDefaultZone());
            ReflectionTestUtils.invokeMethod(openSamlImplementation, "bootstrap");
            return openSamlImplementation;
        }
    }

    default <T extends Saml2Object> T resolveFromXMLFile(Class<T> clazz, String path) throws IOException {
        byte[] xml = StreamUtils.copyToByteArray(new ClassPathResource(path).getInputStream());
        return clazz.cast(openSamlImplementation.resolve(xml, Collections.emptyList(), Collections.emptyList()));
    }

    default <T extends Saml2Object> T resolveFromEncodedXML(Class<T> clazz, String xml) {
        String inflatedXml = openSamlImplementation.inflate(Base64.getDecoder().decode(xml));
        return clazz.cast(openSamlImplementation.resolve(inflatedXml, Collections.emptyList(), Collections.emptyList()));
    }

}
