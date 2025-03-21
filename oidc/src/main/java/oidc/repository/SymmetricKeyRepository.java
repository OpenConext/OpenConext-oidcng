package oidc.repository;

import oidc.model.SymmetricKey;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SymmetricKeyRepository extends MongoRepository<SymmetricKey, String> {

    List<SymmetricKey> findAllByOrderByCreatedDesc();

}
