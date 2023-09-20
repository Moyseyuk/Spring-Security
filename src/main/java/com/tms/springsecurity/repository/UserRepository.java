package com.tms.springsecurity.repository;

import com.tms.springsecurity.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

    User getByLogin(String login);

}
