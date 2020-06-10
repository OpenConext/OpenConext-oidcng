package oidc.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.SneakyThrows;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class RelayState {

    private String clientId;
    private String acrValues;

    @SneakyThrows
    public static RelayState from(String relayState, ObjectMapper objectMapper) {
        return objectMapper.readValue(relayState, RelayState.class);
    }

    @SneakyThrows
    public String toJson(ObjectMapper objectMapper) {
        return objectMapper.writeValueAsString(this);
    }
}
