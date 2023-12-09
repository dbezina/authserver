package com.bezina.authorization.server.mycloud;


import com.bezina.authorization.server.mycloud.DAO.UserRepository;
import com.bezina.authorization.server.mycloud.entity.User;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.*;

@SpringBootApplication
public class MyCloudApplication {

	public static void main(String[] args) {
		SpringApplication.run(MyCloudApplication.class, args);
	}
	@Bean
	public ApplicationRunner dataLoader(UserRepository repo, PasswordEncoder passwordEncoder){
		User user1 = new User("user1",passwordEncoder.encode("password1"),"ROLE_USER");
		user1.setEnabled(true);

		User user2 = new User("user2",passwordEncoder.encode("password2"),"ROLE_ADMIN");
		user2.setEnabled(true);

		User user3 = new User("user3",passwordEncoder.encode("password3"),"ROLE_ADMIN");
		user3.setEnabled(true);

		return args -> {
			if (repo.findByUsername(user1.getUsername()) == null)
				repo.save(user1);
			if (repo.findByUsername(user2.getUsername()) == null)
				repo.save(user2);
			if (repo.findByUsername(user3.getUsername()) == null)
				repo.save(user3);
		};
	}

}
