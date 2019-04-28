package oidc.manage;

import oidc.model.OpenIDClient;
import oidc.repository.OpenIDClientRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.BulkOperations;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class MetadataController {

    @Autowired
    private MongoTemplate mongoTemplate;

    @PostMapping("manage/connections")
    @Transactional
    public ResponseEntity<Void> connections(@RequestBody List<Map<String, Object>> connections) {
        List<OpenIDClient> newClients = connections.stream().map(OpenIDClient::new).collect(Collectors.toList());

        mongoTemplate.bulkOps(BulkOperations.BulkMode.ORDERED, OpenIDClient.class)
                .remove(new Query())
                .insert(newClients)
                .execute();

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

}
