package oidc.endpoints;

import com.fasterxml.jackson.core.type.TypeReference;

import java.util.Map;

public interface MapTypeReference {

    TypeReference<Map<String, Object>> mapTypeReference = new TypeReference<Map<String, Object>>() {
    };
}
