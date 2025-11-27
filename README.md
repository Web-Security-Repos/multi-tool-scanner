# Multi-Tool Security Scanner

A comprehensive security analysis platform that integrates multiple static analysis tools (Semgrep and Snyk Code) to analyze repositories, store results in MongoDB, and provide comparison analytics through an interactive dashboard.

**Part of the Web Security Analysis Dashboard - Task 6 Implementation**

## 🎯 Overview

This tool integrates two industry-leading security scanners to provide comprehensive vulnerability detection:

- **Semgrep**: Fast pattern-based SAST with 1000+ security rules
- **Snyk Code**: AI-powered SAST with deep code analysis

Results are normalized, stored in MongoDB, and can be compared to identify overlapping findings, unique detections, and tool effectiveness.

## 📋 Prerequisites

- **Node.js** v16 or higher
- **MongoDB** connection (MongoDB Atlas recommended)
- **Semgrep** installed (`pip install semgrep` or `brew install semgrep`)
- **Snyk CLI** installed (`npm install -g snyk`)
- **Snyk Account** (free tier) with Snyk Code enabled

## 🚀 Installation

### 1. Clone and Install Dependencies

```bash
cd multi-tool-scanner
npm install
```

### 2. Install Security Tools

**Install Semgrep:**
```bash
# Option 1: via pip
pip install semgrep

# Option 2: via Homebrew (macOS)
brew install semgrep

# Verify installation
semgrep --version
```

**Install Snyk:**
```bash
# Install globally
npm install -g snyk

# Authenticate (opens browser)
snyk auth

# Verify installation
snyk --version
```

**Enable Snyk Code:**
1. Go to https://app.snyk.io/manage/settings
2. Click "Snyk Code" in sidebar
3. Toggle "Enable Snyk Code" to ON
4. Save changes

### 3. Configure Environment

Create `.env` file:

```bash
cp .env.example .env
```

Edit `.env` with your configuration:

```env
# MongoDB Connection
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/websec

# Target Repositories (comma-separated relative or absolute paths)
TARGET_REPOS=../test-reflected-xss-nodejs,../test-sql-injection,../test-command-injection,../test-hardcoded-credentials

# Scan Configuration
SCAN_TIMEOUT=300000
```

## 📖 Usage

### Run Complete Multi-Tool Scan

```bash
npm start
```

This will:
1. Scan all target repositories with Semgrep
2. Scan all target repositories with Snyk Code
3. Parse and normalize results
4. Store findings in MongoDB
5. Display summary statistics

### Run Individual Tools

```bash
# Semgrep only
npm run scan:semgrep

# Snyk Code only
npm run scan:snyk
```

Analyzes stored results to find:
- Common findings (detected by both tools)
- Unique findings (detected by one tool)
- Tool effectiveness metrics
- Overlap percentages

### Run Integration Tests

```bash
npm test
```

Verifies:
- Scanner initialization
- Multi-tool execution
- Result normalization
- Database storage
- Comparison logic

## 📊 Output Format

### Normalized Finding Structure

All tools output findings in this format:

```json
{
  "tool_name": "Semgrep",
  "tool_version": "1.45.0",
  "repository": "test-reflected-xss-nodejs",
  "scan_date": "2025-11-27T10:30:00.000Z",
  "scan_duration_ms": 3157,
  "findings": [
    {
      "rule_id": "javascript.express.security.xss",
      "severity": "high",
      "category": "XSS",
      "message": "Potential XSS vulnerability detected",
      "location": {
        "path": "index.js",
        "start_line": 15,
        "end_line": 15
      }
    }
  ],
  "stats": {
    "total_findings": 4,
    "by_severity": {
      "critical": 0,
      "high": 2,
      "medium": 2,
      "low": 0
    }
  }
}
```

### Severity Mapping

Tools map severity levels as follows:

| Tool Output | Normalized |
|-------------|------------|
| Semgrep ERROR | high |
| Semgrep WARNING | medium |
| Snyk error | high |
| Snyk warning | medium |

### Exclusions

**Semgrep** automatically excludes:
- `node_modules/`
- `.git/`
- `dist/`, `build/`

**Snyk Code** excludes via CLI flag:
- `--exclude=node_modules`

## 📈 Comparison Features

### Overlap Detection

The comparison analyzer identifies:

**Common Findings**: Same vulnerability detected by multiple tools
- Uses fingerprint: `rule_id::path::line::category`
- Helps validate findings (higher confidence)

**Unique Findings**: Detected by only one tool
- Shows tool-specific capabilities
- May indicate false negatives in other tools


### Performance Comparison

Tracks for each tool:
- Scan duration (milliseconds)
- Findings per repository
- Average time per finding

## 🌐 Dashboard Integration

### Backend API Endpoints

**Get Tool Statistics:**
```bash
GET /api/tools/stats
```

**Get Comparison Report:**
```bash
GET /api/tools/comparison/:repoId
```

**Trigger Multi-Tool Scan:**
```bash
POST /api/tools/scan-local
```

### Frontend Access

1. Start backend:
```bash
cd ../dashboard/backend
npm start
```

2. Start frontend:
```bash
cd ../dashboard/frontend
npm run dev
```

3. Visit: `http://localhost:5173/comparison`

Features:
- Tool statistics overview
- Repository selector
- Overlap analysis
- Effectiveness comparison
- Severity breakdown
- Category distribution

## 🧪 Testing

### Test Coverage

- ✅ Scanner initialization
- ✅ Tool execution (Semgrep & Snyk)
- ✅ Output parsing
- ✅ Result normalization
- ✅ Database storage
- ✅ Comparison analysis

### Expected Results

Running `npm test` should show:

```
Semgrep:     8 findings
Snyk Code:   9 findings
Total:       17 findings

By Severity:
  Critical: 1
  High:     8
  Medium:   8
  Low:      0

✅ All tests passed!
```

## 📄 License

MIT

## 👥 Authors

Web Security Repos Team - Task 6 Implementation

---

**For questions or issues, please open an issue on GitHub.**

