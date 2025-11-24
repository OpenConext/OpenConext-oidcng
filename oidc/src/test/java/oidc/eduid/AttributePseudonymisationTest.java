package oidc.eduid;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import oidc.AbstractIntegrationTest;
import oidc.model.EntityType;
import oidc.model.OpenIDClient;
import org.junit.ClassRule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.util.*;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class AttributePseudonymisationTest extends AbstractIntegrationTest {

    @Autowired
    private AttributePseudonymisation attributePseudonymisation;

    @ClassRule
    public static WireMockRule wireMockRule = new WireMockRule(8099);

    @Test
    public void pseudonymise() throws IOException {
        String pseudoEduid = "rp-eduid";
        String eduPersonPrincipalName = "jdoe@example.com";

        Map<String, String> res = new HashMap<>();
        res.put("eduid", pseudoEduid);
        res.put("eduperson_principal_name", eduPersonPrincipalName);

        stubFor(get(urlPathMatching("/attribute-manipulation")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(res))));

        OpenIDClient resourceServer = openIDClient("resource-server-playground-client");
        OpenIDClient openIDClient = openIDClient("mock-sp");
        Map<String, String> pseudonymisedAttributes = attributePseudonymisation.pseudonymise(resourceServer, openIDClient, "rs-eduid").get();

        assertEquals(pseudoEduid, pseudonymisedAttributes.get("eduid"));
        assertEquals(eduPersonPrincipalName, pseudonymisedAttributes.get("eduperson_principal_name"));
    }

    @Test
    public void pseudonymiseWithRSWithoutInstitutionIdentifier() throws IOException {
        Map<String, String> res = new HashMap<>();
        String pseudoEduid = "rp-eduid";
        res.put("eduid", pseudoEduid);
        stubFor(get(urlPathMatching("/attribute-manipulation")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(res))));

        OpenIDClient resourceServer = openIDClient("mock-sp");
        OpenIDClient openIDClient = openIDClient("playground_client");
        Map<String, String> pseudonymisedAttributes = attributePseudonymisation.pseudonymise(resourceServer, openIDClient, "rs-eduid").get();

        assertEquals(pseudoEduid, pseudonymisedAttributes.get("eduid"));
    }

    @Test
    public void pseudonymiseRpIsRs() throws IOException {
        OpenIDClient resourceServer = openIDClient("resource-server-playground-client");
        Optional<Map<String, String>> pseudonymisedAttributes = attributePseudonymisation.pseudonymise(resourceServer, resourceServer, "rs-eduid");

        assertFalse(pseudonymisedAttributes.isPresent());
    }

    @Test
    public void pseudonymiseRpIsRsForInstitutionGUID() {
        String institutionGuid = UUID.randomUUID().toString();
        OpenIDClient resourceServer = new OpenIDClient(Map.of(
            "type", EntityType.OAUTH_RS.getType(),
            "data", Map.of("entityid","rs", "metaDataFields", Map.of("coin:institution_guid", institutionGuid))));
        OpenIDClient openIDClient = new OpenIDClient(Map.of(
            "type", EntityType.OIDC_RP.getType(),
            "data", Map.of("entityid","rp", "metaDataFields", Map.of("coin:institution_guid", institutionGuid))));
        Optional<Map<String, String>> pseudonymisedAttributes = attributePseudonymisation.pseudonymise(resourceServer, openIDClient, "rs-eduid");

        assertFalse(pseudonymisedAttributes.isPresent());
    }

    @Test
    public void pseudonymiseNoEduid() throws IOException {
        OpenIDClient resourceServer = openIDClient("resource-server-playground-client");
        OpenIDClient openIDClient = openIDClient("mock-sp");
        Optional<Map<String, String>> pseudonymisedAttributes = attributePseudonymisation.pseudonymise(resourceServer, openIDClient, null);

        assertFalse(pseudonymisedAttributes.isPresent());
    }

    @Test
    public void pseudonymiseWithError() throws IOException {
        stubFor(get(urlPathMatching("/attribute-manipulation")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withStatus(400)
                .withBody(objectMapper.writeValueAsString(Collections.singletonMap("error", true)))));

        OpenIDClient resourceServer = openIDClient("resource-server-playground-client");
        OpenIDClient openIDClient = openIDClient("mock-sp");
        Optional<Map<String, String>> pseudonymisedAttributes = attributePseudonymisation.pseudonymise(resourceServer, openIDClient, "rs-eduid");

        assertFalse(pseudonymisedAttributes.isPresent());
    }

}
