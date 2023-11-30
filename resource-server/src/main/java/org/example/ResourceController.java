package org.example;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@RestController
public class ResourceController {

    @GetMapping("/resource")
    public String home(HttpServletRequest request) {
        System.out.println(request.getHeaderNames());
        LocalDateTime time = LocalDateTime.now();
        return "Welcome Resource Server! - " + time;
    }

}
