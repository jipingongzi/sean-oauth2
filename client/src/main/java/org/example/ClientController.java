package org.example;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class ClientController {

    @Autowired
    public WelcomeClient welcomeClient;

    @GetMapping("/client")
    public String welcome() {

        String welcome = welcomeClient.getWelcome();
        return "<h1>" +  welcome + "</h1>";
    }
}

