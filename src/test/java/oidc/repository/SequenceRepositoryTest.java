package oidc.repository;

import oidc.AbstractIntegrationTest;
import oidc.model.Sequence;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.junit.Assert.assertEquals;

public class SequenceRepositoryTest extends AbstractIntegrationTest {

    @Autowired
    private SequenceRepository sequenceRepository;

    @Test
    public void incrementSigningKeyId() {
        mongoTemplate.dropCollection(Sequence.class);

        sequenceRepository.incrementSigningKeyId();
        assertEquals(1L, sequenceRepository.currentSigningKeyId().longValue());

        sequenceRepository.incrementSigningKeyId();
        assertEquals(2L, sequenceRepository.currentSigningKeyId().longValue());
    }

    @Test
    public void updateSymmetricKeyId() {
        mongoTemplate.dropCollection(Sequence.class);

        sequenceRepository.updateSymmetricKeyId(1221L);
        assertEquals(1221L, sequenceRepository.currentSymmetricKeyId().longValue());

        sequenceRepository.updateSymmetricKeyId(9999L);
        assertEquals(9999L, sequenceRepository.currentSymmetricKeyId().longValue());
    }
}