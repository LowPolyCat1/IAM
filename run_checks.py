import subprocess
import sys


def run_command(command, check=True):
    try:
        print(f"Running: {command}")
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, check=check
        )
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        return result
    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e}")
        print(f"Error output:\n{e.stderr}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"Command not found: {e}")
        sys.exit(1)


if __name__ == "__main__":
    run_command("cargo build")
    run_command("cargo clippy -- -D warnings")
    run_command("cargo test")
    run_command("cargo audit")

    print("All checks completed successfully!")
