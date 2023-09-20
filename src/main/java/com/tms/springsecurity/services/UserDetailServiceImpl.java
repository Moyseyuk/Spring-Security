package com.tms.springsecurity.services;

import com.tms.springsecurity.model.Role;
import com.tms.springsecurity.model.User;
import com.tms.springsecurity.model.UserSecurity;
import com.tms.springsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserDetailServiceImpl implements UserDetailsService {

    private final UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = repository.getByLogin(username);
        List<Role> roles = user.getRoles();
        List<String> rolesAsString = roles.stream()
                .map(Role::getName)
                .collect(Collectors.toList());
        return new UserSecurity(user.getLogin(), user.getPassword(), rolesAsString);
    }
}
