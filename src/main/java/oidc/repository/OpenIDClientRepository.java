package oidc.repository;

import oidc.model.OpenIDClient;
import oidc.model.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OpenIDClientRepository extends MongoRepository<OpenIDClient, String> {

    OpenIDClient findByClientId(String clientId);

    Optional<OpenIDClient> findOptionalByClientId(String clientId);

    List<OpenIDClient> findByClientIdIn(List<String> clientIdentifiers);
}
