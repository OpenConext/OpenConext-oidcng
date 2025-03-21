package oidc.endpoints;

import java.util.HashMap;

public class FluentMap<K, V> extends HashMap<K, V> {

    public FluentMap p(K key, V value) {
        super.put(key, value);
        return this;
    }
}
