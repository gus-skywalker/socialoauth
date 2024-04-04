package com.lesmonades.socialauth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
public class UserController {

    @GetMapping("/login")
    public String login() {
        return "login.html";
    }

    @GetMapping("/")
    public String home() {
        return "Home - O escolhido foi você. Salame mingue. Sorvete colore.";
    }

    @GetMapping("/user/me")
    public Principal user(Principal principal) {
        return principal;
    }

    @GetMapping("/secured")
    public String secured() {
        return "Eu to funcionando de forma segura!";
    }
}
