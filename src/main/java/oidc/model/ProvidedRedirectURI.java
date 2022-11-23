package oidc.model;


import lombok.Getter;

import java.net.URI;

@Getter
public class ProvidedRedirectURI {

    private final String redirectURI;
    private final URI me;

    public ProvidedRedirectURI(String redirectURI) {
        this.redirectURI = redirectURI;
        this.me = URI.create(redirectURI);
    }

    //the ports may differ, but only for localhost
    public boolean equalsWithLiteralCheckRequired(String uri) {
        URI that = URI.create(uri);
        boolean equals = that.getScheme().equals(me.getScheme()) &&
                that.getHost().equals(me.getHost()) &&
                that.getPath().equals(me.getPath());
        return literalCheckRequired() ?
                (equals && that.getPort() == me.getPort()) : equals;
    }

    private boolean literalCheckRequired() {
        String host = me.getHost();
        return !"127.0.0.1".equals(host) && !"localhost".equals(host);
    }

    @Override
    public String toString() {
        return redirectURI;
    }
}
