package org.example;

import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;


@HttpExchange("http://localhost:8090")
public interface WelcomeClient {

    @GetExchange("/resource")
    String getWelcome();


}
