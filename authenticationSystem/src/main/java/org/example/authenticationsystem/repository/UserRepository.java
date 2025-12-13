package org.example.authenticationsystem.repository;

import org.example.authenticationsystem.model.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository interface for accessing User data from the H2 database.
 * <p>
 * By extending JpaRepository, Spring Data automatically generates the implementation
 * for standard CRUD operations (Save, Find, Delete) without writing SQL.
 */
@Repository
public interface UserRepository extends JpaRepository<UserEntity, Long> {

    /**
     * Custom query method to find a user by their username.
     * Spring Data JPA automatically interprets the method name and creates the query:
     * "SELECT * FROM users WHERE username = ?"
     *
     * @param username The username to search for.
     * @return An Optional containing the UserEntity if found, or empty if not exists.
     */
    Optional<UserEntity> findByUsername(String username);

}