package org.example;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;

@RestController
public class ResourceController {

    @GetMapping("/resource")
    public String home(HttpServletRequest request, Authentication authentication) {
        LocalDateTime time = LocalDateTime.now();
        return "Welcome ResourceServer! - " + time + "<br>" + authentication.getName() + " - " + authentication.getAuthorities();
    }

}
