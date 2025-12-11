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

@Service
public class TokenService {

    private final RSAKey rsaKey;

    public TokenService(RSAKey rsaKey) {
        this.rsaKey = rsaKey;
    }

    // CREAZIONE DEL TOKEN (JWS)
    public String generateToken(String username) throws JOSEException {
        // 1. Crea il firmatario con la chiave PRIVATA
        JWSSigner signer = new RSASSASigner(rsaKey);

        //todo rivere sta parte issuer/claim
        // 2. Prepara il Payload (Claims)
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(username)
                .issuer("https://mia-scuola.ch")
                .expirationTime(Date.from(Instant.now().plusSeconds(3600))) // 1 ora
                .claim("role", "student") // Claim personalizzato
                .build();

        // 3. Crea l'oggetto JWS con l'algoritmo RSA_256
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                claimsSet
        );

        // 4. Firma il token
        signedJWT.sign(signer);

        // 5. Serializza in stringa (formato xxxx.yyyy.zzzz)
        return signedJWT.serialize();
    }

    // VERIFICA DEL TOKEN
    public boolean verifyToken(String token) {
        try {
            // 1. Parsa la stringa in un oggetto SignedJWT
            SignedJWT signedJWT = SignedJWT.parse(token);

            // 2. Crea il verificatore con la chiave PUBBLICA
            JWSVerifier verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());

            // 3. Verifica la firma e la scadenza
            return signedJWT.verify(verifier) &&
                    new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime());

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public String getRoleFromToken(String token) {
        try {
            // 1. Parsa il token
            SignedJWT signedJWT = SignedJWT.parse(token);

            // 2. Crea il verificatore
            JWSVerifier verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());

            // 3. PRIMA verifica la firma e la scadenza (FONDAMENTALE!)
            boolean isSignatureValid = signedJWT.verify(verifier);
            boolean isNotExpired = new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime());

            if (isSignatureValid && isNotExpired) {
                // 4. Se è valido, leggi il claim personalizzato "role"
                // Nota: getStringClaim restituisce null se il campo non esiste
                return signedJWT.getJWTClaimsSet().getStringClaim("role");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null; // Ritorna null se il token non è valido o c'è un errore
    }
}