package oidc.model;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

public class IdentityProviderTest {

    @Test
    public void getId() {
        Map<String, Object> root = new HashMap<>();
        Map<String, Object> data = new HashMap<>();
        data.put("entityid", "entityid");

        Map<String, Object> metaDataFields = new HashMap<>();
        metaDataFields.put("name:en", "name_en");
        metaDataFields.put("name:nl", "name_nl");
        data.put("metaDataFields", metaDataFields);

        root.put("data", data);
        IdentityProvider identityProvider = new IdentityProvider(root);

        assertEquals("entityid", identityProvider.getEntityId());
        assertEquals("name_en", identityProvider.getName());
        assertEquals("name_nl", identityProvider.getNameNl());
    }

}