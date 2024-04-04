package com.lesmonades.socialauth.service;

import com.lesmonades.socialauth.domain.Provider;
import com.lesmonades.socialauth.domain.User;
import com.lesmonades.socialauth.repository.MongoDBUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Optional;
import java.util.function.Consumer;

@Slf4j
@RequiredArgsConstructor
public final class OAuth2UserHandler implements Consumer<OAuth2User> {

    private final MongoDBUserRepository userRepository;

    @Override
    public void accept(OAuth2User user) {
        processOAuthPostLogin(user.getName());
        log.info("Saving first-time user: name=" + user.getName() + ", claims=", user.getAttributes() + ", authorities=" + user.getAuthorities());
    }

    public void processOAuthPostLogin(String username) {
        Optional<User> existUser = userRepository.findUserByUsername(username);

        if (existUser.isEmpty()) {

            User newUser = new User();
            newUser.setUsername(username);
            newUser.setProvider(Provider.GOOGLE);
            newUser.setEnabled(true);

            userRepository.save(newUser);
        }

    }


}
