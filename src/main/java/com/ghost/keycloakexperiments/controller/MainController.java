package com.ghost.keycloakexperiments.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {

    @GetMapping("/home")
    public OAuth2AuthorizedClient home(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) {
        return authorizedClient;
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("admin/home")
    public Authentication adminHome() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

}
