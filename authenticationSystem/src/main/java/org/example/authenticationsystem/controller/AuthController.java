package org.example.authenticationsystem.controller;

import com.nimbusds.jose.JOSEException;
import org.example.authenticationsystem.model.UserEntity;
import org.example.authenticationsystem.repository.UserRepository;
import org.example.authenticationsystem.service.TokenService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Controller responsible for handling authentication requests.
 * It provides endpoints to register users, generate tokens (login), verify, and extract information from JSON Web Tokens (JWS).
 */
@RestController
@CrossOrigin(origins = "*")
public class AuthController {

    private final TokenService tokenService;
    private final UserRepository userRepository;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    /**
     * Constructor for dependency injection.
     *
     * @param tokenService   The service responsible for JWS signing and verification.
     * @param userRepository The repository to interact with the H2 database.
     */
    public AuthController(TokenService tokenService, UserRepository userRepository) {
        this.tokenService = tokenService;
        this.userRepository = userRepository;
    }

    /**
     * Registers a new user in the database.
     * Checks if the username already exists before saving.
     *
     * @param username The desired username.
     * @param password The hashed password.
     * @return A status message indicating success or failure.
     */
    @PostMapping("/register")
    public String register(@RequestParam String username, @RequestParam String password) {
        if (userRepository.findByUsername(username).isPresent()) {
            return "ERROR: User already exists!";
        }

        // 2. HASHING: Trasformiamo "pippo123" in "$2a$10$EixZaY..."
        String hashedPassword = passwordEncoder.encode(password);

        // Salviamo l'utente con la password cifrata
        UserEntity newUser = new UserEntity(username, hashedPassword, "student");
        userRepository.save(newUser);

        return "SUCCESS: Registration completed for user " + username;
    }

    /**
     * Authenticates a user and issues a signed JWT (JWS).
     * It verifies the credentials against the H2 database before issuing the token.
     *
     * @param username The username provided by the client.
     * @param password The password provided by the client.
     * @return A Map containing the generated "access_token".
     * @throws JOSEException If an error occurs during token signing or RuntimeException if login fails.
     */
    @PostMapping("/login")
    public Map<String, String> login(@RequestParam String username, @RequestParam String password) throws JOSEException {
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("ERROR: User not found"));

        // 3. VERIFICA: Non possiamo usare .equals()!
        // Dobbiamo usare .matches(password_in_chiaro, password_nel_db)
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("ERROR: Wrong password!");
        }

        String token = tokenService.generateToken(username);
        return Map.of("access_token", token);
    }

    /**
     * Verifies the validity of a provided JWT.
     * It checks both the digital signature (integrity) and the expiration time.
     *
     * @param authHeader The "Authorization" header containing the Bearer token.
     * @return A success message if the token is valid, otherwise an error message.
     */
    @GetMapping("/verify")
    public String verify(@RequestHeader("Authorization") String authHeader) {
        // The client sends "Bearer <token>", we need to remove the "Bearer " prefix
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7); // Removes the first 7 characters

            boolean isValid = tokenService.verifyToken(token);

            if (isValid) {
                return "SUCCESS: The token is valid and the signature is correct!";
            }
        }
        return "ERROR: Invalid or expired token.";
    }

    /**
     * Extracts and returns the specific "role" claim from the JWT.
     * This demonstrates how to read data embedded inside the token payload.
     *
     * @param authHeader The "Authorization" header containing the Bearer token.
     * @return The role string (e.g., "student") or an error message if the token is missing.
     */
    @GetMapping("/getRole")
    public String getRole(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);

            return tokenService.getRoleFromToken(token);
        }
        return "No token found or invalid header.";
    }
}