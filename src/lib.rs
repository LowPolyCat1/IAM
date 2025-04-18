#[cfg(test)]
pub mod tests;

pub mod database;
pub mod encryption;
pub mod hashing;
pub mod logging;
pub mod server;

pub fn init() {
    dotenvy::dotenv().ok();
}
