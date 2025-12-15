# 🔐 Security by Design: Secure Authentication System (JWT + Spring Boot)

This project is a practical demonstration of a secure architecture for REST APIs, developed for the "Security by Design" module.

The system implements a complete authentication flow using **JSON Web Tokens (JWS)** signed with asymmetric encryption (RSA), data persistence via **H2 Database**, and password security using **BCrypt** hashing.

## 🚀 Key Features

* **Stateless Authentication:** Implementation of JWT (JWS - RFC 7515) digitally signed.
* **User Management:** Registration and Login with persistence on a Relational Database.
* **Password Security:** Passwords are never stored in plain text; they are hashed using **BCrypt**.
* **Asymmetric Encryption:** Token signing via RSA Key Pair (Private Key for signing, Public Key for verification).
* **Role-Based Access Control (RBAC):** Extraction and verification of user roles from token claims.
* **API Documentation:** Full integration with **Swagger/OpenAPI** for testing.
* **Frontend Demo:** A responsive Web Interface (HTML/CSS/JS) to visually test the flow.

## 🛠️ Tech Stack

* **Java 17**
* **Spring Boot 3.x** (Web, Data JPA, Security Crypto)
* **Nimbus JOSE + JWT** (Library for JWS/JWT management)
* **H2 Database** (In-memory SQL Database)
* **Maven** (Dependency Manager)
* **Swagger UI** (API Documentation)

---

## ⚙️ How to Run

### Prerequisites
* JDK 17 or higher installed.
* Maven installed (or use the `mvnw` wrapper included in the project).

### Installation and Execution

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/auth-system.git](https://github.com/your-username/auth-system.git
    cd auth-system
    ```

2.  **Build the project:**
    ```bash
    mvn clean install
    ```

3.  **Run the application:**
    ```bash
    mvn spring-boot:run
    ```

The application will start on port **8080**.

---

## 🌐 Access Points

Once the server is running, you can access the following tools:

| Tool | URL | Description |
| :--- | :--- | :--- |
| **Frontend Demo** | [http://localhost:8080](http://localhost:8080) | GUI for Registration, Login, and Token testing. |
| **Swagger UI** | [http://localhost:8080/swagger-ui/index.html](http://localhost:8080/swagger-ui/index.html) | Interactive API documentation. |
| **H2 Console** | [http://localhost:8080/h2-console](http://localhost:8080/h2-console) | Direct access to the Database. |
| **JWK Endpoint** | [http://localhost:8080/.well-known/jwks.json](http://localhost:8080/.well-known/jwks.json) | Exposes the RSA Public Key (JSON Web Key). |

### ⚠️ H2 Console Configuration
To access the database console, ensure you use these exact credentials:
* **Driver Class:** `org.h2.Driver`
* **JDBC URL:** `jdbc:h2:mem:authDB`
* **User Name:** `sa`
* **Password:** *(leave empty)*

---

## 📡 API Endpoints

### 1. Public Endpoints
* `POST /register`: Registers a new user (saves hashed password).
    * *Params:* `username`, `password`
* `POST /login`: Verifies credentials and issues a JWS (Token).
    * *Params:* `username`, `password`
* `GET /.well-known/jwks.json`: Returns the RSA Public Key.

### 2. Protected Endpoints (Require `Authorization: Bearer <token>` Header)
* `GET /verify`: Verifies the token signature and expiration.
* `GET /getRole`: Extracts the 'role' claim from the token payload.

---

## 📂 Project Structure

```text
src/main/java/org/example/authenticationsystem
├── controller   # HTTP Request Handlers (AuthController)
├── model        # Database Entities (UserEntity)
├── repository   # Data Access Layer (UserRepository)
├── security     # RSA Key Config & Swagger Config
└── service      # Business Logic & JWT Management (TokenService)

src/main/resources
├── static       # Frontend Assets (index.html, style.css)
└── application.properties # H2 Database Configuration
