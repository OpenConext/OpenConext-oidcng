package oidc.model;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

@Getter
@NoArgsConstructor
@EqualsAndHashCode(of = "name")
@ToString(of = "name")
public class Scope implements Serializable {

    private String name;

    private Map<String, String> titles = new HashMap<>();

    private Map<String, String> descriptions = new HashMap<>();

    public Scope(String name) {
        this.name = name;
    }

    @SuppressWarnings("unchecked")
    public Scope(Map<String, Object> jsonRepresentation) {
        this.name = (String) jsonRepresentation.get("name");
        this.titles = (Map<String, String>) jsonRepresentation.getOrDefault("titles", new HashMap<String, String>());
        this.descriptions = (Map<String, String>) jsonRepresentation.getOrDefault("descriptions", new HashMap<String, String>());
    }

}
