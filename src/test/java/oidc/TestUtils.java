package oidc;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.restassured.common.mapper.TypeRef;
import org.apache.commons.io.IOUtils;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public interface TestUtils {

    default String readFile(String path) {
        try {
            return IOUtils.toString(new ClassPathResource(path).getInputStream(), Charset.defaultCharset());
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    TypeRef<Map<String, Object>> mapTypeRef = new TypeRef<Map<String, Object>>() {
    };

    ObjectMapper objectMapper = ObjectMapperWrapper.init();

    default List<Map<String, Object>> relyingParties() throws IOException {
        return objectMapper.readValue(new ClassPathResource("manage/oidc10_rp.json").getInputStream(),
                new TypeReference<List<Map<String, Object>>>() {
                });
    }

    class ObjectMapperWrapper {
        private static ObjectMapper init() {
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.findAndRegisterModules();
            return objectMapper;
        }
    }
}
