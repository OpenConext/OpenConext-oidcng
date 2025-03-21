package oidc.manage;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ServiceProviderTranslationTest {

    @Test
    public void translateServiceProviderEntityId() {
        String s = ServiceProviderTranslation.translateServiceProviderEntityId("https://test");
        assertEquals("https@//test", s);

        s = ServiceProviderTranslation.translateServiceProviderEntityId("https://test@test");
        assertEquals(s, "https@//test@@test", s);

        String originalSPEntityID = "https://test@@@test";
        s = ServiceProviderTranslation.translateServiceProviderEntityId(originalSPEntityID);
        assertEquals(s, "https@//test@@@@@@test", s);

        s = ServiceProviderTranslation.translateClientId(s);
        assertEquals(originalSPEntityID, s);
    }

    @Test
    public void translateClientId() {
        String s = ServiceProviderTranslation.translateClientId("https@//test");
        assertEquals("https://test", s);

        s = ServiceProviderTranslation.translateClientId("https@//test@@test");
        assertEquals(s, "https://test@test", s);
    }
}