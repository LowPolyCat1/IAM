//! src/lib.rs
//!
//! This is the main library module for the IAM project. It defines and exports other modules.

/// The test module
#[cfg(test)]
pub mod tests;

/// The database module
pub mod database;
/// The encryption module
pub mod encryption;
/// The errors module
pub mod errors;
/// The hashing module
pub mod hashing;
/// The jwt module
pub mod jwt;
/// The logging module
pub mod logging;
/// The middleware module
pub mod middleware;
/// The server module
pub mod server;
