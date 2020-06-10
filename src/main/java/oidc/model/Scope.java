package oidc.model;

import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Getter
@NoArgsConstructor
public class Scope implements Serializable {

    private String name;

    private Map<String, String> descriptions = new HashMap<>();

    public Scope(String name) {
        this.name = name;
    }

    @SuppressWarnings("unchecked")
    public Scope(Map<String, Object> jsonRepresentation) {
        this.name = (String) jsonRepresentation.get("name");
        this.descriptions = (Map<String, String>) jsonRepresentation.getOrDefault("descriptions", new HashMap<String, String>());
    }
}
