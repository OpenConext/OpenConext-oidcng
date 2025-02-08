package oidc.model;

import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class ScopeTest {

    @Test
    public void name() {
        Map<String, Object> jsonRepresentation = new HashMap<>();
        jsonRepresentation.put("name", "openid");
        jsonRepresentation.put("descriptions", Collections.singletonMap("en", "English description"));

        Scope scope = new Scope(jsonRepresentation);
        assertEquals("Scope(name=openid)", scope.toString());
    }

}