//! src/tests/tests.rs
//!
//! This module contains integration tests for the IAM project.

#[cfg(test)]
mod tests {
    use crate::encryption::{decrypt_with_nonce, encrypt_with_random_nonce, generate_key};
    use crate::hashing::{hash_random_salt, verify_password};
    use dotenvy::dotenv;
    use std::env;

    #[test]
    fn test_hashing_correct() {
        dotenv().ok();
        let password = "password123";
        let hashed_password = hash_random_salt(password).unwrap();
        assert!(verify_password(password, &hashed_password).is_ok());
    }

    #[test]
    fn test_hashing_incorrect() {
        let password = "password123";
        let hashed_password = hash_random_salt(password).unwrap();
        assert!(verify_password("wrong_password", &hashed_password).is_err());
    }

    #[test]
    fn test_encryption() {
        dotenv().ok();
        let key = generate_key().unwrap();
        let key_bytes: [u8; 32] = key.into();
        let plaintext = "This is a secret message.";
        let encrypted = encrypt_with_random_nonce(&key_bytes, plaintext).unwrap();
        let decrypted = decrypt_with_nonce(&key_bytes, &encrypted).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encryption_key_length() {
        dotenv().ok();
        env::set_var("ENCRYPTION_KEY", "12345678901234567890123456789012");
        let key = generate_key().unwrap();
        let key_bytes: [u8; 32] = key.into();
        assert_eq!(key_bytes.len(), 32);
    }

    use crate::jwt::{extract_user_id_from_jwt, generate_jwt, validate_jwt};

    #[test]
    fn test_jwt_generation() {
        dotenv().ok();
        let user_id = "test_user";
        let token = generate_jwt(user_id.to_string()).unwrap();
        assert!(!token.is_empty());
    }

    #[test]
    fn test_jwt_validation() {
        dotenv().ok();
        let user_id = "test_user";
        let token = generate_jwt(user_id.to_string()).unwrap();
        let claims = validate_jwt(&token).unwrap();
        assert_eq!(claims.sub, user_id);
    }

    #[test]
    fn test_jwt_extraction() {
        dotenv().ok();
        let user_id = "test_user";
        let token = generate_jwt(user_id.to_string()).unwrap();
        let extracted_user_id = extract_user_id_from_jwt(&token).unwrap();
        assert_eq!(extracted_user_id, user_id);
    }

    mod test_middleware {
        use crate::jwt::generate_jwt;
        use crate::middleware::AuthenticationMiddlewareFactory;
        use actix_web::http::header;
        use actix_web::{http::StatusCode, test, web, App, HttpResponse};

        async fn test_route() -> HttpResponse {
            HttpResponse::Ok().finish()
        }

        #[actix_web::test]
        async fn test_authentication_middleware_valid_token() {
            dotenvy::dotenv().ok();
            let user_id = "test_user";
            let token = generate_jwt(user_id.to_string()).unwrap();

            let app = test::init_service(
                App::new()
                    .wrap(AuthenticationMiddlewareFactory::new())
                    .route("/test", web::get().to(test_route)),
            )
            .await;

            let req = test::TestRequest::get()
                .uri("/test")
                .insert_header((header::AUTHORIZATION, format!("Bearer {}", token)))
                .to_request();

            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::OK);
        }

        #[actix_web::test]
        async fn test_authentication_middleware_invalid_token() {
            dotenvy::dotenv().ok();

            let app = test::init_service(
                App::new()
                    .wrap(AuthenticationMiddlewareFactory::new())
                    .route("/test", web::get().to(test_route)),
            )
            .await;

            let req = test::TestRequest::get()
                .uri("/test")
                .insert_header((header::AUTHORIZATION, "Bearer invalid_token".to_string()))
                .to_request();

            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }

        #[actix_web::test]
        async fn test_authentication_middleware_missing_token() {
            dotenvy::dotenv().ok();

            let app = test::init_service(
                App::new()
                    .wrap(AuthenticationMiddlewareFactory::new())
                    .route("/test", web::get().to(test_route)),
            )
            .await;

            let req = test::TestRequest::get().uri("/test").to_request();

            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
    }
}
