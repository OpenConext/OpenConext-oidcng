package oidc.manage;

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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class MetadataController {

    private static final Log LOG = LogFactory.getLog(MetadataController.class);

    @Autowired
    private MongoTemplate mongoTemplate;


    @PostMapping("manage/connections")
//    @Transactional TODO uncomment after upgrade mongodb 4.x
    public ResponseEntity<Void> connections(Authentication authentication,
                                            @RequestBody List<Map<String, Object>> connections,
                                            @RequestParam(name = "forceError", defaultValue = "false") boolean forceError) {
        String name = authentication.getName();
        LOG.info("Starting to provision OIDC clients from push: " + name);

        List<OpenIDClient> newClients = connections.stream().map(OpenIDClient::new).collect(Collectors.toList());

        mongoTemplate.bulkOps(BulkOperations.BulkMode.ORDERED, OpenIDClient.class)
                .remove(new Query())
                .insert(newClients)
                .execute();

        if (forceError) {
            throw new IllegalArgumentException("Forced error");
        }

        LOG.info("Provisioned " + newClients.size() + " OIDC clients from push: " + name);

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

}
