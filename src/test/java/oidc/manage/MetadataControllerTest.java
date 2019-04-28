package oidc.manage;

import com.fasterxml.jackson.core.type.TypeReference;
import oidc.AbstractIntegrationTest;
import oidc.TestUtils;
import oidc.model.OpenIDClient;
import oidc.repository.OpenIDClientRepository;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static oidc.manage.ServiceProviderTranslation.translateServiceProviderEntityId;
import static org.junit.Assert.assertEquals;

@SuppressWarnings("unchecked")
public class MetadataControllerTest extends AbstractIntegrationTest implements TestUtils {

    @Test
    public void connections() throws IOException {
        mongoTemplate.remove(new Query(), OpenIDClient.class);

        postConnections(serviceProviders());
        assertEquals(2L, mongoTemplate.count(new Query(), OpenIDClient.class));

        List<Map<String, Object>> serviceProviders = serviceProviders();
        Map<String, Object> mockSp = serviceProviders.get(0);
        ((Map) mockSp.get("data")).put("entityid", "changed");

        Map<String, Object> mockRp = serviceProviders.get(1);
        ((Map) Map.class.cast(mockRp.get("data")).get("metaDataFields")).put("name:en", "changed");

        postConnections(serviceProviders);

        assertEquals(2L, mongoTemplate.count(new Query(), OpenIDClient.class));

        OpenIDClient openIDClient = mongoTemplate.find(Query.query(Criteria.where("clientId").is("changed")) ,OpenIDClient.class).get(0);
        assertEquals("changed", openIDClient.getClientId());

        openIDClient = mongoTemplate.find(Query.query(Criteria.where("clientId")
                .is(translateServiceProviderEntityId("http://mock-rp"))) ,OpenIDClient.class).get(0);
        assertEquals("changed", openIDClient.getName());
    }

    private void postConnections(List<Map<String, Object>> serviceProviders) throws IOException {
        given()
                .when()
                .header("Content-type", "application/json")
                .auth()
                .preemptive()
                .basic("manage", "secret")
                .body(serviceProviders)
                .post("manage/connections")
                .then()
                .statusCode(201);
    }

}