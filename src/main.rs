use iam::server::start;

#[actix_web::main]
async fn main() {
    start().await;
}
