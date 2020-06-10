package oidc.eduid;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import oidc.AbstractIntegrationTest;
import oidc.model.OpenIDClient;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.junit.Assert.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "cron.node-cron-job-responsible=false",
                "eduid.uri=http://localhost:8099/attribute-manipulation"
        })
public class AttributePseudonymisationTest extends AbstractIntegrationTest {

    @Autowired
    private AttributePseudonymisation attributePseudonymisation;

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(8099);

    @Test
    public void pseudonymise() throws IOException {
        Map<String, String> res = new HashMap<>();
        String pseudoEduid = "rp-eduid";
        String eduPersonPrincipalName = "jdoe@example.com";

        res.put("eduid", pseudoEduid);
        res.put("eduperson_principal_name", eduPersonPrincipalName);

        stubFor(get(urlPathMatching("/attribute-manipulation")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(res))));

        OpenIDClient resourceServer = openIDClient("resource-server-playground-client");
        OpenIDClient openIDClient = openIDClient("mock-sp");

        Map<String, Object> attributes = responseBody("rs-eduid");
        attributes.put("attr", "value");
        Map<String, Object> pseudonymisedAttributes = attributePseudonymisation.pseudonymise(resourceServer, openIDClient, attributes);

        assertEquals(pseudoEduid, pseudonymisedAttributes.get("eduid"));
        assertEquals(eduPersonPrincipalName, pseudonymisedAttributes.get("eduperson_principal_name"));
        assertEquals("value", pseudonymisedAttributes.get("attr"));
    }

    @Test
    public void pseudonymiseWithRSwithoutInstitutionIdentifier() throws IOException {
        Map<String, String> res = new HashMap<>();
        String pseudoEduid = "rp-eduid";
        res.put("eduid", pseudoEduid);
        stubFor(get(urlPathMatching("/attribute-manipulation")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(res))));

        OpenIDClient resourceServer = openIDClient(    "mock-sp");
        OpenIDClient openIDClient = openIDClient("playground_client");

        Map<String, Object> attributes = responseBody("rs-eduid");
        attributes.put("attr", "value");
        Map<String, Object> pseudonymisedAttributes = attributePseudonymisation.pseudonymise(resourceServer, openIDClient, attributes);

        assertEquals(pseudoEduid, pseudonymisedAttributes.get("eduid"));
        assertEquals("value", pseudonymisedAttributes.get("attr"));
    }

    @Test
    public void pseudonymiseRpIsRs() throws IOException {
        OpenIDClient resourceServer = openIDClient("resource-server-playground-client");

        Map<String, Object> attributes = responseBody("rs-eduid");
        Map<String, Object> pseudonymisedAttributes = attributePseudonymisation.pseudonymise(resourceServer, resourceServer, attributes);

        assertEquals("rs-eduid", pseudonymisedAttributes.get("eduid"));
    }


    @Test
    public void pseudonymiseNoEduid() throws IOException {
        OpenIDClient resourceServer = openIDClient("resource-server-playground-client");
        OpenIDClient openIDClient = openIDClient("mock-sp");

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("attr", "value");
        Map<String, Object> pseudonymisedAttributes = attributePseudonymisation.pseudonymise(resourceServer, openIDClient, attributes);

        assertFalse(pseudonymisedAttributes.containsKey("eduid"));
        assertEquals("value", pseudonymisedAttributes.get("attr"));
    }

    @Test
    public void pseudonymiseWithError() throws IOException {
        stubFor(get(urlPathMatching("/attribute-manipulation")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withStatus(400)
                .withBody(objectMapper.writeValueAsString(Collections.singletonMap("error", true)))));

        OpenIDClient resourceServer = openIDClient("resource-server-playground-client");
        OpenIDClient openIDClient = openIDClient("mock-sp");

        Map<String, Object> attributes = responseBody("rs-eduid");
        attributes.put("attr", "value");
        Map<String, Object> pseudonymisedAttributes = attributePseudonymisation.pseudonymise(resourceServer, openIDClient, attributes);

        assertFalse(pseudonymisedAttributes.containsKey("eduid"));
        assertEquals("value", pseudonymisedAttributes.get("attr"));
    }

    @Test
    public void enabled() {
        AttributePseudonymisation subject = new AttributePseudonymisation(null,"user","password",false);
        Map<String, Object> attributes = Collections.singletonMap("k", "v");
        Map<String, Object> result = subject.pseudonymise(null, null, attributes);
        assertEquals(attributes, result);
    }

    private Map<String, Object> responseBody(String eduId) {
        Map<String, Object> res = new HashMap<>();
        res.put("uid", Collections.singletonList("uid"));
        res.put("eduid", eduId);
        return res;
    }

}