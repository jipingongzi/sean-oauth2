package org.example;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class ClientController {

    @Autowired
    private WelcomeClient welcomeClient;
    @Autowired
    private OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    @GetMapping("/client")
    public String welcome(HttpServletRequest request, Authentication authentication) {
        String authorities = authentication.getName() + " - " + authentication.getAuthorities().toString();
        String welcome = welcomeClient.getWelcome();
        return "<h1>" +  welcome + "</h1><h2>" + authorities + "</h2>";
    }
    @GetMapping("/token")
    public String token(Authentication authentication) {
        OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
        OAuth2AuthorizedClient oAuth2AuthorizedClient = oAuth2AuthorizedClientService
                .loadAuthorizedClient(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId(), oAuth2AuthenticationToken.getName());
        String jwtAccessToken = oAuth2AuthorizedClient.getAccessToken().getTokenValue();
        String jwtRefrechToken = oAuth2AuthorizedClient.getRefreshToken().getTokenValue();
        return "<b>JWT Access Token: </b>" + jwtAccessToken + "<br/><br/><b>JWT Refresh Token:  </b>" + jwtRefrechToken;
    }

    @GetMapping("idtoken")
    public String idtoken(@AuthenticationPrincipal OidcUser oidcUser) {
        OidcIdToken oidcIdToken = oidcUser.getIdToken();
        String idTokenValue = oidcIdToken.getTokenValue();
        return "<b>Id Token: </b>" + idTokenValue;
    }
}

