package com.example.gateway.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.List;

@Component
@Order(-1)
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationWebFilter implements WebFilter {

    private static final String AUTHORIZATION_HEADER = HttpHeaders.AUTHORIZATION;
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String ROLE_USER = "ROLE_USER";

    private final JwtService jwtService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String jwt = extractJwtFromRequest(exchange.getRequest());

        if (!StringUtils.hasText(jwt)) {
            return chain.filter(exchange);
        }

        return Mono.fromCallable(() -> {
            if (!jwtService.validateToken(jwt)) {
                return null; // Token expired or invalid
            }
            String username = jwtService.extractUsername(jwt);
            List<GrantedAuthority> authorities = jwtService.extractRoles(jwt);
            boolean hasUserRole = authorities.stream()
                    .anyMatch(a -> ROLE_USER.equals(a.getAuthority()));
            if (!hasUserRole) {
                return null; // Role is not USER
            }
            return new UsernamePasswordAuthenticationToken(username, null, authorities);
        })
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(authentication -> {
                    if (authentication != null) {
                        return chain.filter(exchange)
                                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
                    }
                    return chain.filter(exchange);
                })
                .onErrorResume(e -> {
                    log.debug("Cannot set user authentication: {}", e.getMessage());
                    return chain.filter(exchange);
                });
    }

    private String extractJwtFromRequest(ServerHttpRequest request) {
        String bearerToken = request.getHeaders().getFirst(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length());
        }
        return null;
    }
}
