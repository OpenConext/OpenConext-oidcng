package oidc.endpoints;

import java.util.HashMap;

public class FluentMap extends HashMap<String, String> {

    public FluentMap p(String key, String value) {
        super.put(key, value);
        return this;
    }
}
