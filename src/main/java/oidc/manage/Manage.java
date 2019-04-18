package oidc.manage;

import oidc.model.OpenIDClient;

public interface Manage {

    OpenIDClient client(String clientId);

}
