package org.example;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                //所有请求都需经过授权认证
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated())
                //配置登录URL
                .oauth2Login(oauth2Login ->
                        oauth2Login.loginPage("/oauth2/authorization/myoauth2"))
                //使用默认客户端配置
                .oauth2Client(withDefaults());
        return http.build();
    }
}
