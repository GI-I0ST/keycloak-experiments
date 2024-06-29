package com.ghost.clientpart.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private static final List<String> SOCIAL_PROVIDERS = List.of("google", "facebook", "gitlab", "github");
    private static final String AUTHORITY_CLAIM = "roles";

    private final ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    @Profile("iodc")
    public SecurityFilterChain filterChain(HttpSecurity http)
            throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(auth -> auth
                        .userInfoEndpoint(epConfig -> epConfig
                                .userService(userService())
                                .oidcUserService(oidcUserService())
                        )
                )
                .logout(logout -> logout
                        .logoutSuccessHandler(oidcLogoutSuccessHandler())
                );

        return http.build();
    }

    @Bean
    @Profile("pkce")
    public SecurityFilterChain filterChainPKCE(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(auth -> auth
                        .authorizationEndpoint(cfg -> cfg.authorizationRequestResolver(pkceResolver(clientRegistrationRepository)))
                )
                .logout(logout -> logout
                        .logoutSuccessHandler(oidcLogoutSuccessHandler())
                );

        return http.build();
    }

    @Bean
    public OAuth2AuthorizationRequestResolver pkceResolver(ClientRegistrationRepository repo) {
        var resolver = new DefaultOAuth2AuthorizationRequestResolver(repo, "/oauth2/authorization");
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        return resolver;
    }

    @Bean
    public LogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OidcClientInitiatedLogoutSuccessHandler(this.clientRegistrationRepository);

        // Sets the location that the End-User's User Agent will be redirected to
        // after the logout has been performed at the Provider
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/login");

        return oidcLogoutSuccessHandler;
    }

    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {

        final OidcUserService delegate = new OidcUserService();
        return userRequest -> {
            // Delegate to the default implementation for loading a user
            OidcUser oidcUser = delegate.loadUser(userRequest);

            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
            // Handle different clients
            ClientRegistration cliReg = userRequest.getClientRegistration();
            if (isSocial(cliReg.getClientName())) {
                mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_SOCIAL"));
            }
            else {
                List<SimpleGrantedAuthority> roles = oidcUser.getIdToken().getClaimAsStringList(AUTHORITY_CLAIM)
                        .stream()
                        .filter(role -> role.startsWith("ROLE_"))
                        .map(SimpleGrantedAuthority::new)
                        .toList();

                mappedAuthorities.addAll(roles);
            }

            return new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
        };
    }

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> userService() {

        final OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        return userRequest -> {
            // Delegate to the default implementation for loading a user
            OAuth2User oAuth2User = delegate.loadUser(userRequest);

            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            // Handle different clients
            ClientRegistration cliReg = userRequest.getClientRegistration();
            if (isSocial(cliReg.getClientName())) {
                mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_SOCIAL"));
            } else {
                if (oAuth2User.getAttributes().containsKey(AUTHORITY_CLAIM)) {
                    List<SimpleGrantedAuthority> roles = ((List<String>) oAuth2User.getAttribute(AUTHORITY_CLAIM))
                            .stream()
                            .filter(role -> role.startsWith("ROLE_"))
                            .map(SimpleGrantedAuthority::new)
                            .toList();

                    mappedAuthorities.addAll(roles);
                }
            }

            String userNameAttribute = cliReg.getProviderDetails()
                    .getUserInfoEndpoint()
                    .getUserNameAttributeName();

            return new DefaultOAuth2User(mappedAuthorities, oAuth2User.getAttributes(), userNameAttribute);
        };
    }

    private boolean isSocial(String clientName) {
        return (SOCIAL_PROVIDERS.contains(clientName.toLowerCase()));
    }
}
