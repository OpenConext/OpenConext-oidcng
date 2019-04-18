package oidc.manage;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;

@Configuration
public class ManageConf {

    @Bean
    public Manage manage(@Value("${manage.mock}") boolean manageMock,
                         @Value("${manage.user}") String user,
                         @Value("${manage.password}") String password,
                         @Value("${manage.url}") String manageBaseUrl) throws IOException {
        return manageMock ? new MockManage() : new RemoteManage(user, password, manageBaseUrl);
    }


}
