package oidc.repository;

import oidc.model.DeviceAuthorization;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.Optional;

@Repository
public interface DeviceAuthorizationRepository extends MongoRepository<DeviceAuthorization, String> {

    Optional<DeviceAuthorization> findByDeviceCode(String deviceCode);

    Optional<DeviceAuthorization> findByUserCode(String userCode);

    Long deleteByExpiresAtBefore(Date expiresAt);

}
