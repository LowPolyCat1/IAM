use crate::database::Database;
use crate::errors::custom_errors::CustomError;
use crate::middleware::AuthenticationMiddlewareFactory;
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::HttpRequest;
use actix_web::{get, post, web, App, HttpMessage, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env::var;
use tracing_appender::rolling::Rotation;
use validator::Validate;
use validator_derive::Validate;

/// Struct representing the login request body
#[derive(Debug, Deserialize, Serialize, Validate)]
struct LoginRequest {
    #[validate(email(message = "Email is invalid"))]
    email: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters long"))]
    password: String,
}
/// Struct representing the register request body
#[derive(Debug, Deserialize, Serialize, Validate)]
struct RegisterRequest {
    #[validate(length(min = 1, message = "Firstname is required"))]
    firstname: String,
    #[validate(length(min = 1, message = "Lastname is required"))]
    lastname: String,
    #[validate(length(min = 1, message = "Username is required"))]
    username: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters long"))]
    password: String,
    #[validate(email(message = "Email is invalid"))]
    email: String,
}

#[derive(Debug, Deserialize, Serialize, Validate)]
struct ChangeUsernameRequest {
    #[validate(length(min = 1, message = "Username is required"))]
    username: String,
}

#[derive(Debug, Deserialize, Serialize, Validate)]
struct ChangePasswordRequest {
    #[validate(length(min = 8, message = "Password must be at least 8 characters long"))]
    password: String,
}

/// Application state shared across all routes
#[derive(Clone)]
pub struct AppState {
    /// Database connection
    pub db: Database,
}

/// Starts the Actix Web server.
///
/// # Returns
///
/// A `Result` indicating success or failure.
pub async fn start() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber for logging
    let rolling = tracing_appender::rolling::Builder::new()
        .rotation(Rotation::DAILY)
        .filename_suffix("log")
        .build("D:/VSC/Rust/Projects/current/IAM/logs")?; // Only here until I get logging middleware to work
    tracing_subscriber::fmt().with_writer(rolling).init();
    tracing::info!("Starting Programm!");

    tracing::info!("Loading env");
    // Load environment variables from .env file
    load_dotenv()?;

    // Create a new database connection
    let database = Database::new().await?;

    // Create the application state
    let app_state = AppState {
        db: database.clone(),
    };

    tracing::info!("Getting IP");
    // Get the server IP address from environment variables
    let server_ip = get_server_ip()?;

    tracing::info!("Getting Port");
    // Get the server port as a string from environment variables
    let server_port_string = get_server_port_string()?;

    tracing::info!("Parsing Port");
    // Parse the server port string into a u16
    let server_port = parse_server_port(&server_port_string)?;
    tracing::info!("Setting up server");

    let governor_conf = match GovernorConfigBuilder::default()
        .requests_per_second(2)
        .seconds_per_request(1)
        .burst_size(10)
        .finish()
    {
        Some(governor) => governor,
        None => {
            return Err(Box::new(CustomError::GovernorCreationError(
                "Unknown".to_string(),
            )));
        }
    };

    // Create the Actix Web server
    actix_web::HttpServer::new(move || {
        App::new()
            // Share the application state with all routes
            .app_data(web::Data::new(app_state.clone()))
            .wrap(Governor::new(&governor_conf))
            .wrap(AuthenticationMiddlewareFactory::new())
            // Register the ping route
            .service(ping)
            // Register the register route
            .service(register)
            .service(authenticate_user)
            .service(debug)
            .service(change_username)
            .service(change_password)
    })
    // Bind the server to the specified IP address and port
    .bind((server_ip, server_port))?
    .run()
    .await?;

    tracing::info!("Starting server");
    // Start the server
    Ok(())
}

/// Gets the server IP address from environment variables.
///
/// # Returns
///
/// A `Result` containing the server IP address or a `CustomError` if an error occurs.
fn get_server_ip() -> Result<String, CustomError> {
    match var("SERVER_IP") {
        Ok(server_ip) => {
            tracing::info!("Found SERVER_IP = {}", server_ip);
            Ok(server_ip)
        }
        Err(error) => {
            tracing::error!("Couldn't find SERVER_IP | {}", error);
            Err(CustomError::EnvironmentVariableError(error.to_string()))
        }
    }
}

/// Gets the server port as a string from environment variables.
///
/// # Returns
///
/// A `Result` containing the server port as a string or a `CustomError` if an error occurs.
fn get_server_port_string() -> Result<String, CustomError> {
    match var("SERVER_PORT") {
        Ok(server_port) => {
            tracing::info!("Found SERVER_PORT = {}", server_port);
            Ok(server_port)
        }
        Err(error) => {
            tracing::error!("Couldn't find SERVER_PORT | {}", error);
            Err(CustomError::EnvironmentVariableError(error.to_string()))
        }
    }
}

/// Loads environment variables from the .env file.
///
/// # Returns
///
/// A `Result` containing the server IP address or a `CustomError` if an error occurs.
fn load_dotenv() -> Result<(), CustomError> {
    match dotenvy::dotenv() {
        Ok(pathbuf) => {
            tracing::info!("loaded .env file: {:?}", pathbuf);
            Ok(())
        }
        Err(error) => {
            tracing::error!("Couldn't load env | {}", error);
            Err(CustomError::from(error))
        }
    }
}

/// Parses the server port string into a u16
/// Parses the server port string into a u16.
///
/// # Arguments
///
/// * `server_port_string` - The server port as a string.
///
/// # Returns
///
/// A `Result` containing the server port as a u16 or a `CustomError` if an error occurs.
fn parse_server_port(server_port_string: &str) -> Result<u16, CustomError> {
    match server_port_string.parse::<u16>() {
        Ok(port) => {
            tracing::info!("Successfully parsed port: {}", port);
            Ok(port)
        }
        Err(error) => {
            tracing::error!("Error parsing port | {}", error);
            // Remove unwrap() and propagate the error
            Err(CustomError::ParsingServerPortError(error.to_string()))
        }
    }
}

/// Registers a new user
/// Registers a new user.
///
/// # Arguments
///
/// * `req` - The register request.
/// * `data` - The application state.
///
/// # Returns
///
/// A `Result` indicating success or failure.
#[post("/register")]
async fn register(
    req: web::Json<RegisterRequest>,
    data: web::Data<AppState>,
    http_req: HttpRequest,
) -> impl Responder {
    tracing::info!("Registering user");
    let user_id = http_req
        .extensions()
        .get::<String>()
        .cloned()
        .unwrap_or_else(|| "Unknown".to_string());

    tracing::info!("User ID from token: {}", user_id);

    // Validate the request body
    if let Err(validation_errors) = req.0.validate() {
        tracing::warn!("Validation error: {:?}", validation_errors);
        return HttpResponse::BadRequest().json(validation_errors);
    }

    // Extract the request body
    let firstname = req.0.firstname.clone();
    let lastname = req.0.lastname.clone();
    let username = req.0.username.clone();
    let password = req.0.password.clone();
    let email = req.0.email.clone().to_lowercase();

    // Get the database connection from the application state
    let db = &data.db;

    // hashing is handled in the db.register function
    match db
        .register(firstname, lastname, username, password, email)
        .await
    {
        Ok(_) => {
            tracing::info!("User registered successfully");
            HttpResponse::Created().body("User registered successfully")
        }
        Err(error) => {
            tracing::error!("Error registering user: {}", error);
            match error {
                CustomError::UserAlreadyExists => {
                    HttpResponse::Conflict().body(format!("Error: {}", error))
                }
                _ => HttpResponse::InternalServerError().body(format!("Error: {}", error)),
            }
        }
    }
}

/// Authenticates a user.
///
/// # Arguments
///
/// * `req` - The login request.
///
/// # Returns
///
/// A `Result` indicating success or failure.
#[post("/login")]
async fn authenticate_user(
    req: web::Json<LoginRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    tracing::info!("Authenticating user");
    // Validate the request body
    if let Err(validation_errors) = req.0.validate() {
        tracing::warn!("Validation error: {:?}", validation_errors);
        return HttpResponse::BadRequest().json(validation_errors);
    }

    // Extract the request body
    let email = req.0.email.clone().to_lowercase();
    let password = req.0.password.clone();

    // Get the database connection from the application state
    let db = &data.db;

    // Authenticate the user
    match db.authenticate_user(email, password).await {
        Ok(user) => {
            tracing::info!("User authenticated successfully");
            // Generate JWT
            match crate::jwt::generate_jwt(user.id.to_string()) {
                Ok(token) => HttpResponse::Ok().json(json!({"success": true, "token": token})),
                Err(error) => {
                    tracing::error!("Error generating JWT: {}", error);
                    HttpResponse::InternalServerError()
                        .json(json!({"success": false, "error": "Failed to generate token"}))
                }
            }
        }
        Err(error) => {
            tracing::error!("Error authenticating user: {}", error);
            match error {
                CustomError::InvalidPassword => HttpResponse::Ok().json(json!({"success": false})),
                CustomError::UserNotFound => HttpResponse::Ok().json(json!({"success": false})),
                _ => HttpResponse::InternalServerError().json(json!({"success": false})),
            }
        }
    }
}

/// Pings the server.
///
/// # Returns
///
/// A `Result` containing the string "pong".
#[get("/ping")]
async fn ping(req: HttpRequest) -> impl Responder {
    let user_id = req
        .extensions()
        .get::<String>()
        .cloned()
        .unwrap_or_else(|| "Unknown".to_string());
    format!("pong from user: {}", user_id)
}

#[get("/debug")]
async fn debug(req: HttpRequest) -> impl Responder {
    let user_id = req
        .extensions()
        .get::<String>()
        .cloned()
        .unwrap_or_else(|| "Unknown".to_string());
    format!("Debug: User ID from token: {}", user_id)
}

/// Changes the Username of a user.
///
/// # Arguments
///
/// * `req` - The change username request.
///
/// * `http_req` - The http request.
///
/// # Returns
///
/// A `Result` indicating success or failure.
#[post("/change_username")]
async fn change_username(
    http_req: HttpRequest,
    req: web::Json<ChangeUsernameRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    // Validate the request body
    if let Err(validation_errors) = req.0.validate() {
        tracing::warn!("Validation error: {:?}", validation_errors);
        return HttpResponse::BadRequest().json(validation_errors);
    }
    let new_username = req.0.username;
    let user_id = http_req
        .extensions()
        .get::<String>()
        .cloned()
        .unwrap_or_else(|| "Unknown".to_string());

    match data.db.change_username(user_id, new_username).await {
        Ok(_) => HttpResponse::Ok().json("Successfully changed username"),
        Err(_error) => HttpResponse::InternalServerError().finish(),
    }
}

/// Changes the Password of a user.
///
/// # Arguments
///
/// * `req` - The change username request.
///
/// * `http_req` - The http request.
///
/// # Returns
///
/// A `Result` indicating success or failure.
#[post("/change_password")]
async fn change_password(
    http_req: HttpRequest,
    req: web::Json<ChangePasswordRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    // Validate the request body
    if let Err(validation_errors) = req.0.validate() {
        tracing::warn!("Validation error: {:?}", validation_errors);
        return HttpResponse::BadRequest().json(validation_errors);
    }
    let new_password = req.0.password;
    let user_id = http_req
        .extensions()
        .get::<String>()
        .cloned()
        .unwrap_or_else(|| "Unknown".to_string());

    match data.db.change_password(user_id, new_password).await {
        Ok(_) => HttpResponse::Ok().json("Successfully changed password"),
        Err(_error) => HttpResponse::InternalServerError().finish(),
    }
}
