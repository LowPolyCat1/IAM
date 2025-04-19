use iam::server::start;

#[tokio::main]
async fn main() {
    let _ = start().await;
}
