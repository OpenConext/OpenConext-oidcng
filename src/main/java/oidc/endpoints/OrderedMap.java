package oidc.endpoints;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;

import static java.util.stream.Collectors.toMap;

public interface OrderedMap {

    default <K, V> Map<K, V> sortMap(Map<K, V> map) {
        return map
                .entrySet()
                .stream()
                .sorted(Comparator.comparing(e -> e.getKey().toString()))
                .collect(toMap(Map.Entry::getKey, Map.Entry::getValue, (e1, e2) -> e2, LinkedHashMap::new));
    }

}
