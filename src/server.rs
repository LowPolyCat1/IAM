use crate::database::Database;
use actix_web::{self, get, post, web, App, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::{env::var, process::exit};

const FALLBACK_IP: &str = "127.0.0.1";
const FALLBACK_PORT: &str = "8080";

#[derive(Debug, Deserialize, Serialize)]
struct RegisterRequest {
    firstname: String,
    lastname: String,
    username: String,
    password: String,
    email: String,
}

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
}

pub async fn start() {
    tracing_subscriber::fmt().init();
    tracing::info!("Starting Programm!");

    tracing::info!("Loading env");
    load_dotenv();

    let database = Database::new().await;
    let app_state = AppState {
        db: database.clone(),
    };

    tracing::info!("Getting IP");
    let server_ip = get_server_ip();

    tracing::info!("Getting Port");
    let server_port_string = get_server_port_string();

    tracing::info!("Parsing Port");
    let server_port = parse_server_port(&server_port_string);
    tracing::info!("Setting up server");

    let server = match actix_web::HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .service(ping)
            .service(register)
    })
    .bind((server_ip, server_port))
    {
        Ok(server) => server,
        Err(error) => {
            tracing::error!("couldn't bind to address: \n{}", error);
            exit(1);
        }
    };

    tracing::info!("Starting server");
    match server.run().await {
        Ok(_) => {
            tracing::info!("Server stopped gently");
        }
        Err(error) => {
            tracing::error!("Server stopped with error | {}", error);
        }
    };
}

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

#[post("/register")]
async fn register(req: web::Json<RegisterRequest>, data: web::Data<AppState>) -> impl Responder {
    let firstname = req.firstname.clone();
    let lastname = req.lastname.clone();
    let username = req.username.clone();
    let password = req.password.clone();
    let email = req.email.clone();

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

#[get("/ping")]
async fn ping() -> impl Responder {
    "pong"
}
