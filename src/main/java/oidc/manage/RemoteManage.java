package oidc.manage;

import oidc.model.OpenIDClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.util.CollectionUtils;
import org.springframework.web.client.RestTemplate;

import java.util.*;

import static oidc.manage.ServiceProviderTranslation.translateClientId;

public class RemoteManage implements Manage {

    private final static Logger LOG = LoggerFactory.getLogger(RemoteManage.class);

    private String url;

    private RestTemplate restTemplate = new RestTemplate();
    private HttpHeaders httpHeaders = new HttpHeaders();

    public RemoteManage(String username, String password, String manageBaseUrl) {
        String basicAuth = "Basic " + new String(Base64.getEncoder().encode((username + ":" + password).getBytes()));
        this.url = manageBaseUrl + "/manage/api/internal/search/saml20_sp";

        this.httpHeaders.add(HttpHeaders.CONTENT_TYPE, "application/json");
        this.httpHeaders.add(HttpHeaders.AUTHORIZATION, basicAuth);

        SimpleClientHttpRequestFactory requestFactory = (SimpleClientHttpRequestFactory) restTemplate
                .getRequestFactory();
        requestFactory.setConnectTimeout(10 * 1000);
    }

    private Map<String, Object> body(String entityId) {
        Map<String, Object> res = new HashMap<>();
        res.put("REQUESTED_ATTRIBUTES", Collections.singletonList("oidc"));
        res.put("entityid", entityId);
        return res;
    }

    @Override
    public OpenIDClient client(String clientId) {
        String entityId = translateClientId(clientId);

        LOG.debug("Quering SP metadata entries from {} with client {}", url, entityId);

        ResponseEntity<List> responseEntity = restTemplate.exchange(url, HttpMethod.POST, new HttpEntity<Map>(body(entityId), this.httpHeaders), List.class);
        List res = responseEntity.getBody();
        if (CollectionUtils.isEmpty(res)) {
            throw new IllegalArgumentException("Unknown client " + clientId);
        }
        return new OpenIDClient(Map.class.cast(res.get(0)));
    }
}
