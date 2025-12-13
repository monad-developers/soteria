# 🚦 soteria 
A simple CLI tool that validates Safe transaction hashes in JSON log files.

## Quickstart

### Using CLI
If you simply want to validate Safe transaction hashes in your log files, you can use the CLI tool as follows:
```bash
cargo install --git https://github.com/monad-developers/soteria.git
soteria /path/to/your/logs/directory
```

### Using GitHub Actions
If you want to integrate soteria into your CI/CD pipeline, you can use the GitHub action:
```yaml
uses: monad-developers/soteria-action@v0.1.6
with:
    directory: '/path/to/your/logs/directory'
```

Additionally available inputs:
| Input         | Required? | Default | Description                         |
|---------------|-----------|---------|-------------------------------------|
| directory     | Yes       | N/A     | Directory containing log files.     |
| version       | No        | latest  | Version of soteria to use.          |
| github-token  | No        | N/A     | GitHub token for authentication.    |
| fail-on-error | No        | false   | Whether to fail the action on error.|

### Using Docker
You can also run soteria using Docker. There are two options: using a pre-built image or building the image from source. Images use statically linked binaries and are run in a minimal non-root environment for security.

#### Pre-built image
```bash
docker pull monadfoundation/soteria
```

#### Build from source
```bash
docker build -t soteria .
```

#### Run the image
```bash
docker run -v <path-to-your-logs>:/mnt/data soteria /mnt/data
```
