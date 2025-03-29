package com.ecommerce.userservice.dto;

public class JwtResponse {
    private String token;
    private String message;
    private String role;

    public JwtResponse(String token, String message, String role) {
        this.token = token;
        this.message = message;
        this.role = role;
    }

    // ✅ Getters & Setters
    public String getToken() { return token; }
    public String getMessage() { return message; }
    public String getRole() { return role; }

    public void setToken(String token) { this.token = token; }
    public void setMessage(String message) { this.message = message; }
    public void setRole(String role) { this.role = role; }
}
