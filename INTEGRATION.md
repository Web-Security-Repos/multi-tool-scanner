# Multi-Tool Scanner Integration Guide

This document explains how the multi-tool scanner integrates with the Web Security Analysis Dashboard.

## Architecture

```
multi-tool-scanner/
├── scanners/          # Tool-specific scanners (Semgrep, ESLint)
├── parsers/           # Parse and normalize tool outputs
├── database/          # MongoDB storage integration
├── comparison/        # Compare results across tools
└── index.js           # Main orchestrator

Integrates with:
├── database/models/   # Shared models (Repository, Analysis, Alert)
├── dashboard/backend/ # API endpoints for comparison
└── dashboard/frontend # Comparison UI
```

## Features Implemented

### 1. Semgrep Integration ✅
- Scanner: `scanners/semgrep-scanner.js`
- Parser: `parsers/semgrep-parser.js`
- Runs security-audit rulesets
- Detects: XSS, SQLi, Command Injection, Path Traversal, etc.

### 2. ESLint Security Integration ✅
- Scanner: `scanners/eslint-scanner.js`
- Parser: `parsers/eslint-parser.js`
- Uses: eslint-plugin-security, eslint-plugin-no-unsanitized
- Detects: JavaScript security issues, unsafe patterns

### 3. Result Normalization ✅
- Normalizer: `parsers/normalizer.js`
- Converts different tool outputs to common format
- Maps severity levels consistently
- Creates fingerprints for duplicate detection

### 4. Database Integration ✅
- Storage: `database/storage.js`
- Uses existing models: Repository, Analysis, Alert
- Adds `tool_name` field to differentiate tools
- Stores alongside CodeQL results

### 5. Comparison Analysis ✅
- Analyzer: `comparison/analyzer.js`
- Finds overlap between tools
- Identifies unique detections
- Calculates effectiveness metrics
- Performance comparison

### 6. Backend API Extensions ✅
Added to `dashboard/backend/server.js`:
- `GET /api/tools/comparison/:repoId` - Get comparison report
- `GET /api/tools/analyses` - List analyses by tool
- `GET /api/tools/stats` - Overall tool statistics
- `POST /api/tools/scan-local` - Trigger multi-tool scan

### 7. Dashboard UI ✅
New page: `dashboard/frontend/src/pages/ToolComparison.jsx`
- Overview statistics by tool
- Repository-specific comparison
- Overlap analysis visualization
- Effectiveness metrics
- Severity and category breakdowns
- Trigger local scans from UI

## Usage

### 1. Configure Environment

```bash
cd /Users/harshal/Desktop/websec/multi-tool-scanner
cp .env.example .env
# Edit .env with:
# - MONGODB_URI (connection string)
# - TARGET_REPOS (comma-separated paths to test repos)
```

### 2. Install Dependencies

```bash
# Install Node.js dependencies
npm install

# Install Semgrep
pip install semgrep
# OR
brew install semgrep
```

### 3. Run Scans

```bash
# Run all tools on all target repositories
npm start

# Run specific tool
npm run scan:semgrep
npm run scan:eslint

# Run comparison analysis
npm run compare
```

### 4. Test Integration

```bash
npm test
```

### 5. View in Dashboard

```bash
# Start backend
cd ../dashboard/backend
npm start

# Start frontend (in another terminal)
cd ../dashboard/frontend
npm run dev

# Visit: http://localhost:5173/comparison
```

## Database Schema

The multi-tool scanner uses existing models with tool identification:

### Analysis Model
```javascript
{
  tool_name: "Semgrep" | "ESLint-Security" | "CodeQL",
  tool_version: "1.x.x",
  repository: ObjectId,
  // ... other fields
}
```

### Alert Model
```javascript
{
  analysis: ObjectId,  // Links to Analysis with tool_name
  repository: ObjectId,
  rule_id: String,
  security_severity: "critical" | "high" | "medium" | "low",
  // ... other fields
}
```

## Comparison Logic

### Fingerprinting
Findings are deduplicated using fingerprints:
```
fingerprint = rule_id :: location.path :: start_line :: category
```

### Overlap Detection
- **Common findings**: Detected by 2+ tools (same fingerprint)
- **Unique findings**: Detected by only one tool
- **Effectiveness**: Unique detections / Total detections

### Performance Metrics
- Scan duration (ms)
- Findings per tool
- Detection overlap percentage

## API Endpoints

### Get Comparison for Repository
```bash
GET /api/tools/comparison/:repoId
```
Returns overlap analysis, effectiveness metrics, severity breakdown

### Get Tool Statistics
```bash
GET /api/tools/stats
```
Returns overall statistics for all tools

### Trigger Local Scan
```bash
POST /api/tools/scan-local
```
Runs multi-tool scan in background

## Dashboard Features

### Tool Comparison Page
- Overall statistics cards for each tool
- Repository selector for detailed comparison
- Overlap analysis (common vs unique findings)
- Tool effectiveness table
- Severity comparison matrix
- Category breakdown by tool
- Detailed list of common findings
- Button to trigger new scans

## Testing Checklist

- [x] Semgrep scanner works on test repositories
- [x] ESLint scanner works on JavaScript files
- [x] Results are parsed and normalized correctly
- [x] Database storage works (MongoDB integration)
- [x] Comparison analyzer finds overlaps
- [x] Backend API endpoints return data
- [x] Dashboard displays comparison view
- [x] Local scan trigger works

## Troubleshooting

### Semgrep not found
```bash
pip install semgrep
# OR
brew install semgrep
```

### MongoDB connection failed
- Check MONGODB_URI in .env
- Verify network access in MongoDB Atlas

### No comparison data
- Run `npm start` to generate scan data
- Ensure multiple tools have scanned the same repository

### Dashboard shows empty data
- Verify backend is running (port 3001)
- Check browser console for API errors
- Run data ingestion: `cd database && npm run ingest`

## Next Steps

Possible enhancements:
- Add more tools (Bandit for Python, GoSec for Go)
- Scheduled automatic scans
- Email notifications for new findings
- False positive tracking
- Historical trend analysis
- Export comparison reports (PDF/CSV)

