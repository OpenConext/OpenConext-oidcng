package oidc.model;


import lombok.Getter;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.util.Objects;

@Getter
public class ProvidedRedirectURI {

    private final String redirectURI;
    private final URI me;

    public ProvidedRedirectURI(String redirectURI) {
        this.redirectURI = redirectURI;
        this.me = URI.create(redirectURI);
    }

    public boolean equalsIgnorePort(String uri) {
        URI that = URI.create(uri);
        return that.getScheme().equals(me.getScheme()) &&
                that.getHost().equals(me.getHost()) &&
                that.getPath().equals(me.getPath());
    }

    public boolean literalCheckRequired() {
        String host = me.getHost();
        return !"127.0.0.1".equals(host) && !"localhost".equals(host);
    }

    @Override
    public String toString() {
        return redirectURI;
    }
}
