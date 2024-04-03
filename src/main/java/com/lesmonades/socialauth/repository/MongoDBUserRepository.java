package com.lesmonades.socialauth.repository;

import com.lesmonades.socialauth.domain.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import org.springframework.data.mongodb.repository.Query;

import java.util.Optional;

@Repository
public interface MongoDBUserRepository extends MongoRepository<User, String> {

    Optional<User> findUserByEmail(String email);

    @Query("{username:'?0'}")
    Optional<User> findUserByUsername(String username);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);
}
