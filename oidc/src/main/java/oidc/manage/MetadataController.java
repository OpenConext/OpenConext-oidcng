package oidc.manage;

import oidc.model.EntityType;
import oidc.model.OpenIDClient;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.BulkOperations;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static oidc.model.EntityType.OAUTH_RS;
import static oidc.model.EntityType.OIDC_RP;

@RestController
public class MetadataController {

    private static final Log LOG = LogFactory.getLog(MetadataController.class);

    private final List<String> includedEntities = Stream.of(EntityType.values())
            .map(entityType -> entityType.getType()).toList();

    @Autowired
    private MongoTemplate mongoTemplate;


    @PostMapping("manage/connections")
    @Transactional
    public ResponseEntity<Void> connections(Authentication authentication,
                                            @RequestBody List<Map<String, Object>> connections,
                                            @RequestParam(name = "forceError", defaultValue = "false") boolean forceError) {
        String name = authentication.getName();
        LOG.debug("Starting to provision OIDC clients from push: " + name);

        List<OpenIDClient> newClients = connections.stream()
                .filter(connection -> includedEntities.contains(connection.get("type")))
                .map(OpenIDClient::new)
                .collect(Collectors.toList());

        mongoTemplate.bulkOps(BulkOperations.BulkMode.ORDERED, OpenIDClient.class)
                .remove(new Query())
                .insert(newClients)
                .execute();

        if (forceError) {
            throw new IllegalArgumentException("Forced error");
        }

        LOG.debug("Provisioned " + newClients.size() + " OIDC clients from push: " + name);

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

}
