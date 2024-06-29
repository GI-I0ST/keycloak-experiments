package com.ghost.clientpart.service;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

@Service
@RequiredArgsConstructor
public class ResourceServerService {
    private final RestClient restClient = RestClient.create();
    private final OAuth2AuthorizedClientService authorizedClientService;

    public JsonNode callResourceServer() {
        return restClient
                .get()
                .uri("http://localhost:8081/resource")
                .header("Authorization", "Bearer " + getAccessToken())
                .retrieve()
                .body(JsonNode.class);
    }

    private String getAccessToken() {
        var authn = (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        String authzdId = authn.getAuthorizedClientRegistrationId();
        String name = authn.getName();

        OAuth2AuthorizedClient authzdCli = authorizedClientService.loadAuthorizedClient(authzdId, name);
        OAuth2AccessToken token = authzdCli.getAccessToken();

        return token.getTokenValue();
    }
}
