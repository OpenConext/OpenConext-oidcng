package oidc.repository;

import oidc.model.SigningKey;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SigningKeyRepository extends MongoRepository<SigningKey, String> {

    List<SigningKey> findAllByOrderByCreatedDesc();

}
