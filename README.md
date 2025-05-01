<!-- Thanks to othneildrew for publishing this great template! https://github.com/othneildrew/Best-README-Template/blob/main/BLANK_README.md -->

<a id="readme-top"></a>

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![project_license][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/lowpolycat1/IAM">
    <img src="readme-sections/logo.png" alt="Logo" width="80" height="80">
  </a>

<h3 align="center">iam secure</h3>

  <p align="center">
    A secure Identity and Access Management System
    <br />
    <a href="https://github.com/lowpolycat1/IAM"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <!-- <a href="https://github.com/lowpolycat1/IAM">View Demo</a> -->
    <!-- · -->
    <a href="https://github.com/lowpolycat1/IAM/issues/new?labels=bug&template=bug-report---.md">Report Bug</a>
    ·
    <a href="https://github.com/lowpolycat1/IAM/issues/new?labels=enhancement&template=feature-request---.md">Request Feature</a>
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->
## About The Project

[![Product Name Screen Shot][product-screenshot]]()

This project is a demonstration of an Identity and Access Management (IAM) system built with Rust. It showcases various security features and best practices, including:

* Secure password handling (hashing) using Argon2id with salt
* User data encryption and decryption with ChaCha20-Poly130
* Configuration via environment variables

The project uses Actix-web for building the server and provides basic endpoints for user registration and health checks. It also includes modules for database interaction, encryption, hashing, and logging.

**Note:** This project is purely a demonstration and is not intended for production use.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

[![Rust][Rust-shield]][Rust-url]
[![Reqwest][Reqwest-shield]][Reqwest-url]
[![Tokio][Tokio-shield]][Tokio-url]
[![Serde][Serde-shield]][Serde-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>

[Rust-shield]: https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white
[Rust-url]: https://www.rust-lang.org/
[Reqwest-shield]: https://img.shields.io/badge/Reqwest-000000?style=for-the-badge&logo=reqwest&logoColor=white
[Tokio-shield]: https://img.shields.io/badge/Tokio-000000?style=for-the-badge&logo=tokio&logoColor=white
[Tokio-url]: https://tokio.rs/
[Serde-shield]: https://img.shields.io/badge/Serde-000000?style=for-the-badge&logo=serde&logoColor=white
[Serde-url]: https://serde.rs/

<!-- GETTING STARTED -->
## Getting Started

To get a local copy up and running follow these simple steps.

### Prerequisites

* Rust
* Cargo

### Installation

1. Clone the repo

    ```sh
    git clone https://github.com/lowpolycat1/IAM.git
    ```

2. Rename the [env_example](./env_example) file to `.env` and change the settings

    ```
    SERVER_IP = "0.0.0.0"
    SERVER_PORT = "8080"
    DOCKER_EXPOSED_PORT = "8080"
    DATABASE_PATH = "rocksdb:/var/lib/surrealdb"
    ENCRYPTION_KEY = "00000000000000000000000000000000"
    DATABASE_NAMESPACE = "test"
    DATABASE_NAME = "test"
    ```

3. Build the project

    ```sh
    cargo build --release
    ```

4. Run the project

    ```sh
    cargo run --release
    ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Docker

1. Clone the repo

    ```sh
    git clone https://github.com/lowpolycat1/IAM.git
    ```

2. Rename the [env_example](./env_example) file to `.env` and change the settings

    ```
    SERVER_IP = "0.0.0.0"
    SERVER_PORT = "8080"
    DOCKER_EXPOSED_PORT = "8080"
    DATABASE_PATH = "rocksdb:/var/lib/surrealdb"
    ENCRYPTION_KEY = "00000000000000000000000000000000"
    DATABASE_NAMESPACE = "test"
    DATABASE_NAME = "test"
    ```

3. Build the project

    ```sh
    docker build -t iam .
    ```

4. Run the project

    ```sh
    docker run -d -p {SERVER_IP}:{SERVER_PORT}:{DOCKER_EXPOSED_PORT} iam
    ```

#### Python Script

Alternatively you can simply run the [python script](/run_docker.py)

_Note: Docker is building this in --release mode: this may take _**A GOOD WHILE**_ (10+ min) if you want this to be faster you can remove the `--release` in the Dockerfile_

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- USAGE EXAMPLES -->
## Usage

This is a demonstration of the project and can be used as a foundation to build upon. Use this space to show useful examples of how a project can be used. Additional screenshots, code examples and demos work well in this space. You may also link to more resources.

_For more examples, please refer to the [Documentation]()_

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- ROADMAP -->
## Roadmap

* [x] Secure config management using .env
* [x] Password hashing using Argon2
* [x] Data encryption using ChaCha20-Poly130
* [ ] API endpoints
  * [x] /register
  * [x] /login
  * [x] /change_username
  * [ ] /change_email
  * [x] /change_password
  * [ ] /reset_password
* [x] Portability via Docker
* [x] JWT Token authentication
* [x] Rate limiting
* [ ] Using a Cryptographically secure RNG

##### Maybes

* [ ] HTTPS everywhere for data in transit
* [ ] Implementing database Migration service

See the [open issues](https://github.com/lowpolycat1/IAM/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

**Note:** This project is not actively maintained.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Top contributors

<a href="https://github.com/lowpolycat1/IAM/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=LowPolyCat1/IAM" alt="contrib.rocks image" />
</a>

<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTACT -->
## Contact

lowpolycat1

Project Link: [https://github.com/lowpolycat1/IAM](https://github.com/lowpolycat1/IAM)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- ACKNOWLEDGMENTS -->
<!-- ## Acknowledgments

* []()
* []()
* []() -->

<!-- <p align="right">(<a href="#readme-top">back to top</a>)</p> -->

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/lowpolycat1/IAM.svg?style=for-the-badge
[contributors-url]: https://github.com/lowpolycat1/IAM/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/lowpolycat1/IAM.svg?style=for-the-badge
[forks-url]: https://github.com/lowpolycat1/IAM/network/members
[stars-shield]: https://img.shields.io/github/stars/lowpolycat1/IAM.svg?style=for-the-badge
[stars-url]: https://github.com/lowpolycat1/IAM/stargazers
[issues-shield]: https://img.shields.io/github/issues/lowpolycat1/IAM.svg?style=for-the-badge
[issues-url]: https://github.com/lowpolycat1/IAM/issues
[license-shield]: https://img.shields.io/github/license/lowpolycat1/IAM.svg?style=for-the-badge
[license-url]: https://github.com/lowpolycat1/IAM/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/your_linkedin_username
[product-screenshot]: images/screenshot.png
[Reqwest-url]: https://docs.rs/reqwest/latest/reqwest/
