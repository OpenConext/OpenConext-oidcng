package oidc.eduid;

import oidc.model.OpenIDClient;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Service
public class AttributePseudonymisation {

    private static final Log LOG = LogFactory.getLog(AttributePseudonymisation.class);

    private final RestTemplate restTemplate;
    private final HttpHeaders headers;
    private final URI eduIdUri;
    private final boolean enabled;

    public AttributePseudonymisation(@Value("${eduid.uri}") URI eduIdUri,
                                     @Value("${eduid.user}") String user,
                                     @Value("${eduid.password}") String password,
                                     @Value("${eduid.enabled}") boolean enabled) {
        this.restTemplate = new RestTemplate();
        this.restTemplate.setErrorHandler(new FaultTolerantResponseErrorHandler());
        this.eduIdUri = eduIdUri;
        this.enabled = enabled;

        this.headers = new HttpHeaders();
        this.headers.setContentType(MediaType.APPLICATION_JSON);
        this.headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        this.headers.setBasicAuth(user, password);
    }

    /**
     * The Resource Server (RS) needs to be able to identify the user and to make this possible we ask eduID ALA to
     * provide us with the scoped eduID for this RS and the EPPN of the user at his / hers Home Institution. This
     * scenario will only work if the user has linked his / hers eduID account with the RS / Home Institution.
     *
     * @param resourceServer the API owner RS
     * @param openIDClient   the owner of the access token who is calling an API endpoint of the resourceServer
     * @param attributes     the user attributes
     * @return the manipulated attributes
     */
    public Map<String, Object> pseudonymise(OpenIDClient resourceServer, OpenIDClient openIDClient, Map<String, Object> attributes) {
        if (enabled && attributes.containsKey("eduid") && !resourceServer.getClientId().equals(openIDClient.getClientId())) {
            HttpEntity<?> requestEntity = new HttpEntity<>(headers);
            String uriString = UriComponentsBuilder.fromUri(eduIdUri)
                    .queryParam("uid", ((List<String>)attributes.get("uid")).get(0))
                    .queryParam("sp_entity_id", resourceServer.getClientId())
                    .queryParam("sp_institution_guid", resourceServer.getInstitutionGuid())
                    .toUriString();
            ResponseEntity<Map<String, String>> responseEntity =
                    restTemplate.exchange(uriString, HttpMethod.GET, requestEntity, new ParameterizedTypeReference<Map<String, String>>() {
            });
            if (responseEntity.getStatusCode().is2xxSuccessful()) {
                Map<String, String> body = responseEntity.getBody();
                LOG.info(String.format("Pseudonymise result %s for RS %s, RP %s", body, resourceServer.getClientId(), openIDClient.getClientId()));
                attributes.putAll(body);
            } else {
                attributes.remove("eduid");
                LOG.error(String.format("Error %s occurred in pseudonymise for RS %s, RP %s, attributes %s",
                        requestEntity.getBody(), resourceServer.getClientId(), openIDClient.getClientId(), attributes));
            }
        }
        return attributes;
    }

}
