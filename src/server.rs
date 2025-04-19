use crate::database::Database;
use actix_web::{self, get, post, web, App, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::{env::var, process::exit};
use validator::Validate;
use validator_derive::Validate;

// Fallback IP address if not found in environment variables
const FALLBACK_IP: &str = "127.0.0.1";
// Fallback port if not found in environment variables
const FALLBACK_PORT: &str = "8080";

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

/// Application state shared across all routes
#[derive(Clone)]
pub struct AppState {
    /// Database connection
    pub db: Database,
}

/// Starts the Actix Web server
pub async fn start() {
    // Initialize tracing subscriber for logging
    tracing_subscriber::fmt().init();
    tracing::info!("Starting Programm!");

    tracing::info!("Loading env");
    // Load environment variables from .env file
    load_dotenv();

    // Create a new database connection
    let database = Database::new().await;
    // Create the application state
    let app_state = AppState {
        db: database.clone(),
    };

    tracing::info!("Getting IP");
    // Get the server IP address from environment variables
    let server_ip = get_server_ip();

    tracing::info!("Getting Port");
    // Get the server port as a string from environment variables
    let server_port_string = get_server_port_string();

    tracing::info!("Parsing Port");
    // Parse the server port string into a u16
    let server_port = parse_server_port(&server_port_string);
    tracing::info!("Setting up server");

    // Create the Actix Web server
    let server = match actix_web::HttpServer::new(move || {
        App::new()
            // Share the application state with all routes
            .app_data(web::Data::new(app_state.clone()))
            // Register the ping route
            .service(ping)
            // Register the register route
            .service(register)
    })
    // Bind the server to the specified IP address and port
    .bind((server_ip, server_port))
    {
        Ok(server) => server,
        Err(error) => {
            tracing::error!("couldn't bind to address: \n{}", error);
            exit(1);
        }
    };

    tracing::info!("Starting server");
    // Start the server
    match server.run().await {
        Ok(_) => {
            tracing::info!("Server stopped gently");
        }
        Err(error) => {
            tracing::error!("Server stopped with error | {}", error);
        }
    };
}

/// Gets the server IP address from environment variables
fn get_server_ip() -> String {
    match var("SERVER_IP") {
        Ok(server_ip) => {
            tracing::info!("Found SERVER_IP = {}", server_ip);
            server_ip
        }
        Err(error) => {
            tracing::error!("Couldn't find SERVER_IP | {}", error);
            FALLBACK_IP.to_string()
        }
    }
}

/// Gets the server port as a string from environment variables
fn get_server_port_string() -> String {
    match var("SERVER_PORT") {
        Ok(server_port) => {
            tracing::info!("Found SERVER_PORT = {}", server_port);
            server_port
        }
        Err(error) => {
            tracing::error!("Couldn't find SERVER_PORT | {}", error);
            FALLBACK_PORT.to_string()
        }
    }
}

/// Loads environment variables from the .env file
fn load_dotenv() {
    match dotenvy::dotenv() {
        Ok(pathbuf) => {
            tracing::info!("loaded .env file: {:?}", pathbuf);
        }
        Err(error) => {
            tracing::error!("Couldn't load env | {}", error);
        }
    };
}

/// Parses the server port string into a u16
fn parse_server_port(server_port_string: &str) -> u16 {
    match server_port_string.parse::<u16>() {
        Ok(port) => {
            tracing::info!("Successfully parsed port: {}", port);
            port
        }
        Err(error) => {
            tracing::error!("Error parsing port | {}", error);
            tracing::warn!("using fallback port {}", FALLBACK_PORT);
            FALLBACK_PORT.parse::<u16>().unwrap_or(8080)
        }
    }
}

/// Registers a new user
#[post("/register")]
async fn register(req: web::Json<RegisterRequest>, data: web::Data<AppState>) -> impl Responder {
    // Validate the request body
    if let Err(validation_errors) = req.0.validate() {
        return HttpResponse::BadRequest().json(validation_errors);
    }

    // Extract the request body
    let firstname = req.0.firstname.clone();
    let lastname = req.0.lastname.clone();
    let username = req.0.username.clone();
    let password = req.0.password.clone();
    let email = req.0.email.clone();

    // Get the database connection from the application state
    let db = &data.db;

    // hashing is handled in the db.register function
    match db
        .register(firstname, lastname, username, password, email)
        .await
    {
        Ok(message) => HttpResponse::Ok().body(message),
        Err(error) => HttpResponse::InternalServerError().body(format!("Error: {}", error)),
    }
}

/// Pings the server
#[get("/ping")]
async fn ping() -> impl Responder {
    "pong"
}
