package com.lesmonades.socialauth.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
@Slf4j
public class UserController {

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/")
    public String home(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient client) {
        log.info("Autenticathed userId : " + client.getPrincipalName() + " with access_token : " + client.getAccessToken().getTokenValue());
        return "profile";
    }

    @GetMapping("/user/me")
    public String user(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient client,
                       @AuthenticationPrincipal OidcUser oidcUser) {

        System.out.println(client.toString());
        return client.toString();
/*        return String.format("""
        <h2> Access Token: %s </h2>
        <h2> Id Token: %s </h2>
        <h2> Claims: %s </h2>
          """.formatted(client.getAccessToken().getTokenValue(),
                oidcUser.getIdToken().getTokenValue() != null ? oidcUser.getIdToken().getTokenValue() : "",
                oidcUser.getClaims() != null ? oidcUser.getClaims() : ""));*/
    }

    @GetMapping("/secured")
    public String secured() {
        return "Eu to funcionando de forma segura!";
    }
}
