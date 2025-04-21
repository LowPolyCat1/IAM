# Use a specific Rust image (consider bullseye or slim)
FROM rust:bullseye

WORKDIR /app

COPY . .

ARG LLVM_VER=20
RUN echo "deb http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-$LLVM_VER main" >> /etc/apt/sources.list
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN apt-get update && apt-get install -y clang-$LLVM_VER lldb-$LLVM_VER lld-$LLVM_VER clangd-$LLVM_VER

RUN cargo build --release

# Set the command to run the application
CMD ["cargo", "run", "--release"]