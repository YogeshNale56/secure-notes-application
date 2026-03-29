package com.secure.notes.config;

import com.secure.notes.models.AppRole;
import com.secure.notes.models.Role;
import com.secure.notes.models.User;
import com.secure.notes.repositories.RoleRepository;
import com.secure.notes.security.jwt.JwtUtils;
import com.secure.notes.security.services.UserDetailsImpl;
import com.secure.notes.services.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Autowired
    private final UserService userService;

    @Autowired
    private final JwtUtils jwtUtils;

    @Autowired
    RoleRepository roleRepository;

    @Value("${frontend.url}")
    private String frontendUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
        DefaultOAuth2User principal = (DefaultOAuth2User) authentication.getPrincipal();
        Map<String, Object> attributes = principal.getAttributes();
        String email = attributes.getOrDefault("email", "").toString();
        String name = attributes.getOrDefault("name", "").toString();
        String clientRegistrationId = oAuth2AuthenticationToken.getAuthorizedClientRegistrationId();

        String username;
        String idAttributeKey;

        if ("github".equals(clientRegistrationId)) {
            username = attributes.getOrDefault("login", "").toString();
            idAttributeKey = "id";
        } else if ("google".equals(clientRegistrationId)) {
            username = email.split("@")[0];
            idAttributeKey = "sub";
        } else {
            username = email.split("@")[0];
            idAttributeKey = "sub";
        }

        System.out.println("OAuth2 Login Success: " + email + " : " + name + " : " + username);

        User user = userService.findByEmail(email).orElseGet(() -> {
            User newUser = new User();
            Role userRole = roleRepository.findByRoleName(AppRole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Default role not found"));
            newUser.setRole(userRole);
            newUser.setEmail(email);
            newUser.setUserName(username);
            newUser.setSignUpMethod(clientRegistrationId);
            return userService.registerUser(newUser);
        });

        // Update Security Context with database authorities
        DefaultOAuth2User oauthUser = new DefaultOAuth2User(
                List.of(new SimpleGrantedAuthority(user.getRole().getRoleName().name())),
                attributes,
                idAttributeKey
        );
        Authentication securityAuth = new OAuth2AuthenticationToken(
                oauthUser,
                List.of(new SimpleGrantedAuthority(user.getRole().getRoleName().name())),
                clientRegistrationId
        );
        SecurityContextHolder.getContext().setAuthentication(securityAuth);

        // JWT TOKEN LOGIC
        Set<SimpleGrantedAuthority> authorities = new HashSet<>(List.of(new SimpleGrantedAuthority(user.getRole().getRoleName().name())));

        // Create UserDetailsImpl instance for JWT generation
        UserDetailsImpl userDetails = new UserDetailsImpl(
                user.getUserId(),
                user.getUserName(),
                user.getEmail(),
                null,
                user.isTwoFactorEnabled(),
                authorities
        );

        // Generate JWT token
        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        // Redirect to the frontend with the JWT token
        String targetUrl = UriComponentsBuilder.fromUriString(frontendUrl + "/oauth2/redirect")
                .queryParam("token", jwtToken)
                .build().toUriString();

        this.setAlwaysUseDefaultTargetUrl(true);
        this.setDefaultTargetUrl(targetUrl);
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
