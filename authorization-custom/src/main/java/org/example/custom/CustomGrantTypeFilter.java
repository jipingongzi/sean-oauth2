package org.example.custom;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.JwtUtils;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class CustomGrantTypeFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;

    public CustomGrantTypeFilter(AuthenticationManager authenticationManager,
                                 UserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String grantType = request.getParameter("grant_type");
        if (!"password".equals(grantType)) {
            filterChain.doFilter(request, response);
            return;
        }

        String username = request.getParameter("username");
        String password = request.getParameter("password");

        UserDetails user = userDetailsService.loadUserByUsername(username);

        if (user != null && user.getPassword().equals(password)) {
            // 在这里生成 JWT token 或其他 token 格式，然后返回给客户端
            JwtUtils jwtUtils = new JwtUtils();
            String accessToken = jwtUtils.generateToken(user);


            Map<String, String> responseBody = new HashMap<>();
            responseBody.put("access_token", accessToken);
            responseBody.put("refresh_token", "test refresh token");

            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.toString());

            ObjectMapper objectMapper = new ObjectMapper();
            PrintWriter out = response.getWriter();
            objectMapper.writeValue(out, responseBody);
            out.flush();

        } else {
            throw new BadCredentialsException("Invalid username or password");
        }
    }
}