package org.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.web.SecurityFilterChain;

@SpringBootApplication
public class AuthorizationServerCustom {
    public static void main(String[] args) {
        ApplicationContext applicationContext = SpringApplication.run(AuthorizationServerCustom.class, args);

        OAuth2TokenEndpointFilter tokenEndpointFilter = (OAuth2TokenEndpointFilter) ((SecurityFilterChain)applicationContext.getBean("asSecurityFilterChain"))
                .getFilters().stream().filter(f -> f instanceof  OAuth2TokenEndpointFilter)
                .findFirst().get();
        tokenEndpointFilter.setAuthenticationConverter(applicationContext.getBean(MyAuthenticationConverter.class));
    }
}