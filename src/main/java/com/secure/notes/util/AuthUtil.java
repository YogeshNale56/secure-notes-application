package com.secure.notes.util;

import com.secure.notes.models.User;
import com.secure.notes.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class AuthUtil {

    @Autowired
    UserRepository userRepository;

    public Long loggedInUserId() {
        Authentication authenticaion = SecurityContextHolder.getContext().getAuthentication();
        User user =userRepository.findByUserName(authenticaion.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));
        return user.getUserId();
    }

    public User loggedInUser() {
        Authentication authenticaion = SecurityContextHolder.getContext().getAuthentication();
        return userRepository.findByUserName(authenticaion.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

    }

}
