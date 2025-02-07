package oidc.model;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class QueryString {

    private final Map<String, String> keyValues;

    public QueryString(HttpServletRequest request) {
        String queryString = request.getQueryString();
        if (StringUtils.hasText(queryString)) {
            String[] splitted = queryString.split("&");
            this.keyValues = Stream.of(splitted)
                    .map(paramPair -> paramPair.split("="))
                    .filter(paramPair -> paramPair.length == 2)
                    .collect(Collectors.toMap(keyValue -> keyValue[0].toLowerCase(), keyValue -> keyValue[1]));
        } else {
            keyValues = new HashMap<>();
        }
    }

    public String getStateValue() {
        return keyValues.get("state");
    }
}
