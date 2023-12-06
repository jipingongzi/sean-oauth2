package org.example;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;

import java.time.*;

@Component
public class MyAuthenticationConverter implements AuthenticationConverter {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private RegisteredClientRepository clientRepository;

    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter("grant_type");
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        String clientId = request.getParameter("client_id");
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (userDetails != null && passwordEncoder.matches(password, userDetails.getPassword())) {
            RegisteredClient client = clientRepository.findByClientId(clientId);
            JwtUtils jwtUtils = new JwtUtils();
            Instant now = Instant.now();
            ZonedDateTime zonedDateTime = ZonedDateTime.of(LocalDateTime.now().toLocalDate().plusDays(1), LocalDateTime.now().toLocalTime(),  ZoneId.systemDefault());
            Instant end = zonedDateTime.toInstant();
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, password, userDetails.getAuthorities());

            return new OAuth2AccessTokenAuthenticationToken(client, usernamePasswordAuthenticationToken,
                    new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, jwtUtils.generateToken(userDetails), now, end));
        }
        return null;
    }
}
