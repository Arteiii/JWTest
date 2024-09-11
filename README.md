# JWTest

This application is designed for testing purposes, specifically to cycle refreshing tokens and short-lived session
tokens. It provides a hybrid solution that combines the simplicity and statelessness of JWT (JSON Web Tokens) with the
features of non-JWT tokens (kinda).

## How It Works

1. **User Authentication and Token Issuance:**
    - When a user logs in, they receive a refresh token.
      *This token is stored in an SQLite database for this demonstration.*

2. **Requesting a Session Token with a Refresh Token:**
    - The user can request a JWT session token by providing the refresh token obtained at login.

3. **Accessing Protected Resources:**
    - The user can access secure endpoints by including the JWT session token in the `Authorization` header of their
      requests.

4. **Token Expiry and Refreshing:**
    - If the JWT session token expires, the user can request a new session token using the refresh token.
    - Upon requesting a new session token:
        - The old refresh token is invalidated and removed from the database.
        - A new refresh token and a new JWT session token are generated and provided to the user.

5. **Single-Use Refresh Tokens:**
    - Each refresh token can only be used once. After its first use, it becomes invalid, ensuring it cannot be reused
      for subsequent refresh requests.

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.
