# 🚦 soteria 
A simple CLI tool that validates Safe transaction hashes in JSON log files. This is
a metarepo that contains the CLI tool, a GitHub action, and a Docker image for easy integration into various workflows.

## Quickstart

### Install from source
To install soteria from source, ensure you have Rust and Cargo installed. Then, you can use the CLI tool as follows:
```bash
cargo install --git https://github.com/monad-developers/soteria.git
soteria /path/to/your/logs/directory
```

### Build and install from source
To build soteria from source, ensure you have Rust and Cargo installed. Then, clone the repository and build the project:
```bash
git clone https://github.com/monad-developers/soteria.git
cd soteria
cargo install --path .
soteria /path/to/your/logs/directory
```

### Using GitHub Actions
If you want to integrate soteria into your CI/CD pipeline, you can use the GitHub action:
```yaml
- name: Run soteria
  id: soteria
  uses: monad-developers/soteria-action@v0.1.7
  with:
    directory: '/path/to/your/logs/directory'
```

A full list of available flags for the GitHub action is provided below:
| Input           | Required? | Default  | Description                          |
|-----------------|-----------|----------|--------------------------------------|
| `directory`     | Yes       | N/A      | Directory containing log files.      |
| `version`       | No        | `latest` | Version of soteria to use.           |
| `github-token`  | No        | N/A      | GitHub token for authentication.     |
| `fail-on-error` | No        | `true`   | Whether to fail the action on error. |

### Using Docker
You can also run soteria using Docker. There are two options: using a pre-built image or building the image from source. Images use statically linked binaries and are run in a minimal non-root environment for security.

#### Pre-built image
```bash
docker pull monadfoundation/soteria
```

#### Build from source
```bash
git clone https://github.com/monad-developers/soteria.git
cd soteria
docker build -t soteria .
```

#### Run the image
```bash
docker run -v <path-to-your-logs>:/mnt/data soteria /mnt/data
```
