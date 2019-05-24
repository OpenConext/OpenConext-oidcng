package oidc.repository;

import oidc.AbstractIntegrationTest;
import oidc.model.Sequence;
import oidc.model.SigningKey;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.junit.Assert.*;

public class SequenceRepositoryTest extends AbstractIntegrationTest {

    @Autowired
    private SequenceRepository sequenceRepository;

    @Test
    public void increment() {
        mongoTemplate.dropCollection(Sequence.class);

        sequenceRepository.increment();
        assertEquals(1L, sequenceRepository.currentSequence().longValue());

        sequenceRepository.increment();
        assertEquals(2L, sequenceRepository.currentSequence().longValue());
    }

}