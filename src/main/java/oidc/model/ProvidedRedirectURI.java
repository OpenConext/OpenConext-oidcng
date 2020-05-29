package oidc.model;


import lombok.AllArgsConstructor;
import lombok.Getter;

import java.net.URI;
import java.util.Objects;

@AllArgsConstructor
@Getter
public class ProvidedRedirectURI {

    private String redirectURI;
    private boolean providedByRequest;

    public boolean equalsIgnorePort(String uri) {
        URI that = URI.create(uri);
        URI me = URI.create(redirectURI);
        return that.getScheme().equals(me.getScheme()) &&
            that.getHost().equals(me.getHost()) && that.getPath().equals(me.getPath());
    }

    @Override
    public String toString() {
        return redirectURI;
    }
}
