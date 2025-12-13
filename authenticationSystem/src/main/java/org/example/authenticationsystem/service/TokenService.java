package org.example.authenticationsystem.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;

/**
 * Service responsible for managing the lifecycle of JSON Web Tokens (JWS).
 * It handles the creation (signing), verification, and parsing of tokens.
 * <p>
 * It uses RSA asymmetric encryption:
 * - The PRIVATE key is used to SIGN the token (generate).
 * - The PUBLIC key is used to VERIFY the token.
 */
@Service
public class TokenService {

    private final RSAKey rsaKey;

    // Constants for token configuration
    private static final String ISSUER = "https://auth.security-project.local";
    private static final int EXPIRATION_SECONDS = 3600; // 1 hour

    /**
     * Constructor injection for the RSA Key Pair.
     * @param rsaKey The RSA Key bean defined in KeyConfig.
     */
    public TokenService(RSAKey rsaKey) {
        this.rsaKey = rsaKey;
    }

    /**
     * Generates a signed JWS (JSON Web Signature) for a specific user.
     *
     * @param username The subject of the token (the user logging in).
     * @return A serialized String representing the JWS (e.g., "header.payload.signature").
     * @throws JOSEException If the signing process fails.
     */
    public String generateToken(String username) throws JOSEException {
        // 1. Create the Signer using the PRIVATE key
        // Only this server can sign tokens because only this server has the private key.
        JWSSigner signer = new RSASSASigner(rsaKey);

        // 2. Prepare the Payload (Claims)
        // This defines the "passport" content.
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(username)                                      // "sub": Who is this token for?
                .issuer(ISSUER)                                         // "iss": Who created this token?
                .expirationTime(Date.from(Instant.now().plusSeconds(EXPIRATION_SECONDS))) // "exp": When does it die?
                .claim("role", "student")                         // "role": Custom claim (hardcoded for now)
                .build();

        // 3. Create the JWS object
        // We specify the algorithm (RSA 256) and the Key ID (kid) in the header.
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                claimsSet
        );

        // 4. Sign the token
        // This calculates the signature based on Header + Payload + Private Key.
        signedJWT.sign(signer);

        // 5. Serialize to String
        return signedJWT.serialize();
    }

    /**
     * Verifies if a provided token string is valid.
     * Checks:
     * 1. Is the signature correct? (Using Public Key)
     * 2. Is the token expired?
     *
     * @param token The raw token string (without "Bearer ").
     * @return true if valid, false otherwise.
     */
    public boolean verifyToken(String token) {
        try {
            // 1. Parse the String into a SignedJWT object
            SignedJWT signedJWT = SignedJWT.parse(token);

            // 2. Create the Verifier using the PUBLIC key
            // Anyone with the public key can verify, but they cannot sign.
            JWSVerifier verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());

            // 3. Verify Signature AND Expiration
            boolean isSignatureValid = signedJWT.verify(verifier);
            boolean isNotExpired = new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime());

            return isSignatureValid && isNotExpired;

        } catch (Exception e) {
            // Log the error in a real app (e.g., Logger.error(...))
            System.err.println("Token verification failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Extracts the "role" claim from a valid token.
     *
     * @param token The raw token string.
     * @return The role string (e.g., "student") or null if invalid.
     */
    public String getRoleFromToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());

            // Always re-verify before trusting the data!
            if (signedJWT.verify(verifier) && new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime())) {
                return signedJWT.getJWTClaimsSet().getStringClaim("role");
            }
        } catch (Exception e) {
            System.err.println("Error extracting role: " + e.getMessage());
        }
        return null;
    }
}