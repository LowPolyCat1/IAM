# Stage 1: Build the application
FROM rust:bullseye AS builder

WORKDIR /app

COPY . .

ARG LLVM_VER=20
RUN echo "deb http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-$LLVM_VER main" >> /etc/apt/sources.list
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN apt-get update && apt-get install -y clang-$LLVM_VER lldb-$LLVM_VER lld-$LLVM_VER clangd-$LLVM_VER

RUN cargo build --release

# Stage 2: Create a smaller runtime image
FROM debian:bullseye-slim

WORKDIR /app

COPY --from=builder /app/target/release/iam /app/iam
COPY .env /app/.env

ARG DOCKER_EXPOSED_PORT
ENV PORT=$DOCKER_EXPOSED_PORT

EXPOSE $PORT

CMD ["/app/iam"]
