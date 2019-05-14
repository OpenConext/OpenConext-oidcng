package oidc.repository;

import oidc.AbstractIntegrationTest;
import oidc.model.AccessToken;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.test.util.ReflectionTestUtils;

import javax.swing.*;
import java.util.Collections;
import java.util.Date;

import static java.util.Collections.singletonList;
import static org.junit.Assert.assertEquals;

public class AccessTokenRepositoryTest extends AbstractIntegrationTest {

    @Autowired
    private AccessTokenRepository subject;

    @Test(expected = EmptyResultDataAccessException.class)
    public void findByValue() {
        subject.findByValue("nope");
    }

    @Test
    public void findByValueOptional() {
        assertEquals(false, subject.findOptionalAccessTokenByValue("nope").isPresent());
    }

    @Test
    public void findByInnerValue() {
        String value = RandomStringUtils.random(3200, true, true);
        subject.insert(new AccessToken(value,"sub","clientId", singletonList("openid"), new Date(),false));

        AccessToken accessToken = subject.findByValue(value);
        assertEquals(value, ReflectionTestUtils.getField(accessToken, "innerValue"));

        assertEquals(true, subject.findOptionalAccessTokenByValue(value).isPresent());
    }


}