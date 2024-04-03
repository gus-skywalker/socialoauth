package com.lesmonades.socialauth.domain;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.OffsetDateTime;
import java.util.Collection;

@Data
@Document(collection = "user")
@NoArgsConstructor
public class User {

    @Id
    private String id;
    private String username;
    private String password;
    private String email;
    private Language language;
    private Collection<UserRole> userRole;
    @CreatedDate
    private OffsetDateTime createdAt;
    private boolean enabled;

    private Provider provider;

    public Provider getProvider() {
        return provider;
    }

    public void setProvider(Provider provider) {
        this.provider = provider;
    }
}
