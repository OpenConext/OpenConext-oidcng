package oidc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

@SpringBootApplication
@EnableMongoRepositories("oidc.repository")
public class OidcServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(OidcServerApplication.class, args);
	}

}
