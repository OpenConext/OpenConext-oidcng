package oidc.repository;

import oidc.model.SigningKey;
import oidc.model.SymmetricKey;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SymmetricKeyRepository extends MongoRepository<SymmetricKey, String> {

    List<SymmetricKey> findAllByOrderByCreatedDesc();

    default Optional<SymmetricKey> findPrimaryKey() {
        return findByKeyId(SymmetricKey.PRIMARY_KEY);
    }

    Optional<SymmetricKey> findByKeyId(String keyId);
}
