//! src/lib.rs
//!
//! This is the main library module for the IAM project. It defines and exports other modules.

#[cfg(test)]
pub mod tests;

pub mod database;
pub mod encryption;
pub mod errors;
pub mod hashing;
pub mod jwt;
pub mod logging;
pub mod middleware;
pub mod server;
