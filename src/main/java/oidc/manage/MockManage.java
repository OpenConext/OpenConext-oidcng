package oidc.manage;

import com.fasterxml.jackson.databind.ObjectMapper;
import oidc.model.OpenIDClient;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@SuppressWarnings("unchecked")
public class MockManage implements Manage {

    private List<OpenIDClient> clients;

    public MockManage() throws IOException {
        List<Map<String, Object>> res = new ObjectMapper().readValue(new ClassPathResource("manage/service_providers.json").getInputStream(), List.class);
        this.clients = res.stream().map(m -> new OpenIDClient(m)).collect(Collectors.toList());
    }

    @Override
    public OpenIDClient client(String clientId) {
        return clients.stream().filter(c -> c.getClientId().equals(clientId))
                .findAny().orElseThrow(() -> new IllegalArgumentException("Unknown client " + clientId));
    }
}
