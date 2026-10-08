package com.ecogrid.auth;

import com.ecogrid.auth.entity.User;
import com.ecogrid.auth.repository.UserRepository;
import com.ecogrid.auth.service.AuthService;
import com.ecogrid.auth.dto.LoginRequest;
import com.ecogrid.auth.dto.RegisterRequest;
import com.ecogrid.auth.security.JwtUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private AuthService authService;

    @Test
    void testRegister_duplicateEmail() {
        RegisterRequest req = new RegisterRequest();
        req.setEmail("test@ecogrid.com");
        when(userRepository.existsByEmail("test@ecogrid.com")).thenReturn(true);
        assertThrows(RuntimeException.class, () -> authService.register(req));
    }

    @Test
    void testLogin_invalidCredentials() {
        LoginRequest req = new LoginRequest();
        req.setEmail("notfound@ecogrid.com");
        req.setPassword("wrong");
        when(userRepository.findByEmail("notfound@ecogrid.com")).thenReturn(Optional.empty());
        assertThrows(RuntimeException.class, () -> authService.login(req));
    }

    @Test
    void testGetUserById_notFound() {
        when(userRepository.findById(99L)).thenReturn(Optional.empty());
        assertThrows(RuntimeException.class, () -> authService.getUserById(99L));
    }

    @Test
    void testGetUserById_found() {
        User user = new User();
        user.setId(1L);
        user.setEmail("alice@ecogrid.com");
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        User result = authService.getUserById(1L);
        assertEquals("alice@ecogrid.com", result.getEmail());
    }
}
