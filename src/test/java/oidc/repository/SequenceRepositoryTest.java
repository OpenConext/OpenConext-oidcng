package oidc.repository;

import oidc.AbstractIntegrationTest;
import oidc.model.Sequence;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.junit.Assert.assertEquals;

public class SequenceRepositoryTest extends AbstractIntegrationTest {

    @Autowired
    private SequenceRepository sequenceRepository;
    private String newKeyId = "new_key_id";
    private String newKeyId2 = "new_key_id" + 2;

    @Test
    public void udateSigningKeyId() {
        mongoTemplate.dropCollection(Sequence.class);

        sequenceRepository.updateSigningKeyId(newKeyId);
        assertEquals(newKeyId, sequenceRepository.currentSigningKeyId());

        sequenceRepository.updateSigningKeyId(newKeyId2);
        assertEquals(newKeyId2, sequenceRepository.currentSigningKeyId());
    }

    @Test
    public void updateSymmetricKeyId() {
        mongoTemplate.dropCollection(Sequence.class);

        sequenceRepository.updateSymmetricKeyId(newKeyId);
        assertEquals(newKeyId, sequenceRepository.currentSymmetricKeyId());

        sequenceRepository.updateSymmetricKeyId(newKeyId2);
        assertEquals(newKeyId2, sequenceRepository.currentSymmetricKeyId());
    }
}