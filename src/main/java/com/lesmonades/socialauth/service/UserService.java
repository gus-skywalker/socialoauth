package com.lesmonades.socialauth.service;

import com.lesmonades.socialauth.domain.Provider;
import com.lesmonades.socialauth.domain.User;
import com.lesmonades.socialauth.repository.MongoDBUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final MongoDBUserRepository repo;

    public void processOAuthPostLogin(String username) {
        Optional<User> existUser = repo.findUserByUsername(username);

        if (existUser.isEmpty()) {

            User newUser = new User();
            newUser.setUsername(username);
            newUser.setProvider(Provider.GOOGLE);
            newUser.setEnabled(true);

            repo.save(newUser);
        }

    }
}
