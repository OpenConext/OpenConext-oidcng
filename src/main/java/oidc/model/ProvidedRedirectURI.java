package oidc.model;


import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class ProvidedRedirectURI {

    private String redirectURI;
    private boolean providedByRequest;



}
