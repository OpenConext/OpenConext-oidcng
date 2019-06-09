package oidc.repository;

import oidc.model.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends MongoRepository<User, String> {

    User findUserBySub(String sub);

    Optional<User> findOptionalUserBySub(String sub);

    Long deleteBySubNotIn(List<String> subs);
}
