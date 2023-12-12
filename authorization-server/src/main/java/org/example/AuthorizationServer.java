package org.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;

@SpringBootApplication
public class AuthorizationServer {
    public static void main(String[] args) {
        ApplicationContext context = SpringApplication.run(AuthorizationServer.class, args);
        String[] names = context.getBeanDefinitionNames();
        for (int i = 0; i < names.length; i++) {
            System.out.println(names[i]);
        }
        System.out.println(1);
    }
}