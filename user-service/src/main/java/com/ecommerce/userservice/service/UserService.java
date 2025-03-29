package com.ecommerce.userservice.service;


import com.ecommerce.userservice.dto.JwtResponse;
import com.ecommerce.userservice.dto.LoginRequest;
import com.ecommerce.userservice.dto.UserRegistrationDTO;
import com.ecommerce.userservice.exception.UserAlreadyExistsException;
import com.ecommerce.userservice.model.Role;
import com.ecommerce.userservice.model.User;
import com.ecommerce.userservice.repository.UserRepository;
import com.ecommerce.userservice.security.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }
    // Register New User
    public String registerUser(UserRegistrationDTO userRegistrationDTO) {
        logger.info("Registering new user: {}", userRegistrationDTO.getEmail());
        // Check if user already exists
        if(userRepository.findByEmail(userRegistrationDTO.getEmail()).isPresent()) {
            logger.warn("User registration failed - Email already exists: {}", userRegistrationDTO.getEmail());
            throw new RuntimeException("User with this email already exists");
        }

        // If no role is provided, assign CUSTOMER as default
        Role assignedRole = (userRegistrationDTO.getRole() != null) ? userRegistrationDTO.getRole() : Role.CUSTOMER;

        // Hash password
        String hashedPassword = passwordEncoder.encode(userRegistrationDTO.getPassword());

        // Save user
        User newUser = User.builder()
                .name(userRegistrationDTO.getName())
                .email(userRegistrationDTO.getEmail())
                .password(hashedPassword)
                .phone(userRegistrationDTO.getPhone())
                .role(assignedRole)
                .build();

        userRepository.save(newUser);
        logger.info("User registered successfully: {}", newUser.toString());
        return "User registered successfully!";
    }
    // User Login
    public JwtResponse loginUser(LoginRequest loginRequest) {
        logger.info("Login request for user: {}", loginRequest.getEmail());
        Optional<User> userOptional = userRepository.findByEmail(loginRequest.getEmail());
        if(userOptional.isEmpty()) {
            logger.warn("User with email {} does not exist", loginRequest.getEmail());
            throw new BadCredentialsException("Invalid email or password");
        }
        User user = userOptional.get();
        if(!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            logger.info("Login failed - Incorrect password for user: {}", loginRequest.getEmail());
            throw new BadCredentialsException("Invalid password");
        }
        //Generate JWT Token
        String token = jwtUtil.generateToken(user.getEmail(), user.getRole().name());
        logger.info("Login successful for user: {} with token {}", loginRequest.getEmail(), token);
        return new JwtResponse(token, "Login successful", user.getRole().name());
    }
    public String logoutUser(String token) {
        logger.info("Logout request received for token: {}", token);

        jwtUtil.invalidateToken(token);
        logger.info("Token Blacklisted Successfully");

        return "User logged out successfully";
    }
}
