package org.ghost.serverpart.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class MainController {
    @GetMapping("/resource")
    public Authentication getAuthentication() {
        log.info("Rest /resource");
        return SecurityContextHolder.getContext().getAuthentication();
    }
}
