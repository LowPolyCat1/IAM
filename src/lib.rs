#[cfg(test)]
pub mod tests;

pub mod database;
pub mod logging;
pub mod server;

pub fn init() {
    dotenvy::dotenv().ok();
}
