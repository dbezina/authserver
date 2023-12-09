package com.bezina.authorization.server.mycloud.DAO;

import com.bezina.authorization.server.mycloud.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.Repository;

public interface UserRepository extends CrudRepository<User, String> {
    User findByUsername(String username);
}
