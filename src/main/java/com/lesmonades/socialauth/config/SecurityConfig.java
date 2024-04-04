package com.lesmonades.socialauth.config;

import com.lesmonades.socialauth.controller.OAuthController;
import com.lesmonades.socialauth.config.oauth.CustomAuthorizationRedirectFilter;
import com.lesmonades.socialauth.config.oauth.CustomAuthorizationRequestResolver;
import com.lesmonades.socialauth.config.oauth.CustomAuthorizedClientService;
import com.lesmonades.socialauth.config.oauth.CustomStatelessAuthorizationRequestRepository;
import com.lesmonades.socialauth.service.CustomOauth2UserService;
import com.lesmonades.socialauth.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.http.MediaType;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import com.lesmonades.socialauth.domain.CustomOAuth2User;
import java.io.IOException;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final OAuthController oauthController;
    private final CustomOauth2UserService oauth2UserService;
    private final UserService userService;
    private final CustomAuthorizedClientService customAuthorizedClientService;
    private final CustomAuthorizationRedirectFilter customAuthorizationRedirectFilter;
    private final CustomAuthorizationRequestResolver customAuthorizationRequestResolver;
    private final CustomStatelessAuthorizationRequestRepository customStatelessAuthorizationRequestRepository;


    @Bean
    SecurityFilterChain configure(HttpSecurity http) throws Exception {
             http
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers( "/", "/login", "/login.html","/oauth/**").permitAll();
                    try {
                        auth.anyRequest().authenticated()
                                .and()
                                    .formLogin()
                                    .loginPage("/login").permitAll()
                                .and()
                                    .oauth2Login()
                                    .loginPage("/login")
                                    .userInfoEndpoint()
                                    .userService(oauth2UserService)
                                .and()
                                .successHandler((request, response, authentication) -> {
                                    CustomOAuth2User oauthUser = (CustomOAuth2User) authentication.getPrincipal();
                                    userService.processOAuthPostLogin(oauthUser.getEmail());
                                    response.sendRedirect("/list");
                                });
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                })
                .formLogin(withDefaults());
             return http.build();
    }
//    @Bean
//    @SneakyThrows
//    SecurityFilterChain securityFilterChain(HttpSecurity http) {
//        http
//                .authorizeHttpRequests(authorize -> {
//                    authorize.anyRequest().permitAll();
//                })
//                // Disable "JSESSIONID" cookies
//                .sessionManagement(config -> {
//                    config.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//                })
//                // OAuth2 (social logins)
//                .oauth2Login(oauth2Login -> {
//                    oauth2Login.authorizationEndpoint(subconfig -> {
//                                subconfig.baseUri(OAuthController.AUTHORIZATION_BASE_URL);
//                                subconfig.authorizationRequestResolver(this.customAuthorizationRequestResolver);
//                                subconfig.authorizationRequestRepository(this.customStatelessAuthorizationRequestRepository);
//                    });
//                    oauth2Login.redirectionEndpoint(subconfig -> {
//                        subconfig.baseUri(OAuthController.CALLBACK_BASE_URL + "/*");
//                    });
//                    oauth2Login.authorizedClientService(this.customAuthorizedClientService);
//                    oauth2Login.successHandler(this.oauthController::oauthSuccessResponse);
//                    oauth2Login.failureHandler(this.oauthController::oauthFailureResponse);
//                })
//                // Filters
//                .addFilterBefore(this.customAuthorizationRedirectFilter, OAuth2AuthorizationRequestRedirectFilter.class)
//                // Auth exceptions
//                .exceptionHandling(exception -> {
//                    exception.accessDeniedHandler(this::accessDenied);
//                    exception.authenticationEntryPoint(this::accessDenied);
//                }).oauth2Client();
//        return http.build();
//    }

    @SneakyThrows
    private void accessDenied(HttpServletRequest request, HttpServletResponse response, Exception authException) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{ \"error\": \"Access Denied\" }");
    }

}
