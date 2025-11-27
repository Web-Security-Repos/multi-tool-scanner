# Multi-Tool Security Scanner

Integrates Semgrep and Snyk Code security scanners with the Web Security Analysis Dashboard.

## Setup

```bash
npm install
pip install semgrep  # or: brew install semgrep
npm install -g snyk
snyk auth
```

## Usage

```bash
npm run scan:all      # Run all tools
npm run scan:semgrep  # Semgrep only
npm run scan:snyk     # Snyk Code only
npm run compare       # Compare results
```

## Configuration

Edit `.env` with MongoDB URI and target repositories.

