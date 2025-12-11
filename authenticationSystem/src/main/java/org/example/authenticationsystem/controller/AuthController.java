package org.example.authenticationsystem.controller;

import com.nimbusds.jose.JOSEException;
import org.example.authenticationsystem.service.TokenService;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@CrossOrigin(origins = "*")
public class AuthController {

    private final TokenService tokenService;

    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    // Corrisponde a: fetch(..., { method: 'POST' }) su /login
    @PostMapping("/login")
    public Map<String, String> login(@RequestParam String username) throws JOSEException {
        // Genera il token JWS
        String token = tokenService.generateToken(username);
        // Restituisce un JSON: { "access_token": "ey..." } che il tuo JS si aspetta
        return Map.of("access_token", token);
    }

    // Corrisponde a: fetch(..., { headers: { 'Authorization': ... } }) su /verify
    @GetMapping("/verify")
    public String verify(@RequestHeader("Authorization") String authHeader) {
        // Il tuo JS invia "Bearer eyJhb...", dobbiamo togliere "Bearer "
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7); // Rimuove i primi 7 caratteri

            boolean isValid = tokenService.verifyToken(token);

            if (isValid) {
                return "SUCCESSO: Il token è valido e la firma è corretta!";
            }
        }
        return "ERRORE: Token non valido o scaduto.";
    }


    @GetMapping("/getRole")
    public String getRole(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            // Chiama il service solo se abbiamo un token
            return tokenService.getRoleFromToken(token);
        }
        return "Nessun token trovato o header non valido";
    }

}
