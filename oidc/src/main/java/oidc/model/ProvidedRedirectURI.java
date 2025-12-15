package oidc.model;


import lombok.Getter;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.util.Objects;

@Getter
public class ProvidedRedirectURI {

    private final String redirectURI;
    private final URI me;
    private final boolean strictRedirectUriCheck = true;

    public ProvidedRedirectURI(String redirectURI) {
        this.redirectURI = redirectURI;
        this.me = URI.create(redirectURI);
    }

    //the ports may differ, but only for localhost
    public boolean equalsWithLiteralCheckRequired(String uri) {
        URI that = URI.create(uri);
        if (StringUtils.hasText(that.getFragment())) {
            return false;
        }
        boolean equals = that.getScheme().equals(me.getScheme()) &&
                that.getHost().equals(me.getHost()) &&
                that.getPath().equals(me.getPath());
        if (strictRedirectUriCheck) {
            equals = equals && Objects.equals(that.getQuery(), me.getQuery());
        }
        return literalCheckRequired() ?
                (equals && that.getPort() == me.getPort()) : equals;
    }

    private boolean literalCheckRequired() {
        String host = me.getHost();
        return !"127.0.0.1".equals(host) && !"localhost".equals(host) && !"[::1]".equals(host);
    }

    @Override
    public String toString() {
        return redirectURI;
    }
}
