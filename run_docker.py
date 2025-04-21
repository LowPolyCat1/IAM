import os
import subprocess
from dotenv import load_dotenv

if __name__ == "__main__":

    load_dotenv()

    server_ip = os.getenv("SERVER_IP")
    server_port = os.getenv("SERVER_PORT")
    docker_exposed_port = os.getenv("DOCKER_EXPOSED_PORT")
    image_name = "iam-secure"

    if not server_ip or not server_port:
        raise ValueError("SERVER_IP or SERVER_PORT is missing in .env file!")

    build_command = [
        "docker",
        "build",
        "-t",
        image_name,
        ".",
    ]

    print(f"Building Docker image: {' '.join(build_command)}")
    subprocess.run(build_command, check=True)

    run_command = [
        "docker",
        "run",
        "-d",
        "-p",
        f"{server_ip}:{server_port}:{docker_exposed_port}",
        image_name,
    ]

    print(f"Running Docker container: {' '.join(run_command)}")
    subprocess.run(run_command, check=True)
