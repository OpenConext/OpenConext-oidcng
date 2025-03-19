package oidc.model;

public enum EntityType {

    OIDC_RP("oidc10_rp"), OAUTH_RS("oauth20_rs"), SRAM("sram");

    private final String type;

    EntityType(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }
}
