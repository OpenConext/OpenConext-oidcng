package oidc;

import org.junit.Test;

public class OidcServerApplicationTest {

    @Test
    public void main() {
        OidcServerApplication.main(new String[]{"--server.port=8088"});
    }
}