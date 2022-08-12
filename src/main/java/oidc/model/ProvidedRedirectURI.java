package oidc.model;


import lombok.AllArgsConstructor;
import lombok.Getter;

import java.net.URI;

@AllArgsConstructor
@Getter
public class ProvidedRedirectURI {

    private String redirectURI;

    public boolean equalsIgnorePort(String uri) {
        URI that = URI.create(uri);
        URI me = URI.create(redirectURI);
        return that.getScheme().equals(me.getScheme()) &&
                that.getHost().equals(me.getHost()) &&
                that.getPath().equals(me.getPath());
    }

    @Override
    public String toString() {
        return redirectURI;
    }
}
