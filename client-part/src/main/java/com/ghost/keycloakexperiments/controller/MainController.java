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

    @GetMapping("/authentication")
    public Authentication publicAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("admin/authentication")
    public Authentication adminAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    @PreAuthorize("hasRole('ROLE_SOCIAL')")
    @GetMapping("social/authentication")
    public Authentication socialAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

}
