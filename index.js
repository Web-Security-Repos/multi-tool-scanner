require('dotenv').config();
const SemgrepScanner = require('./scanners/semgrep-scanner');
const SnykScanner = require('./scanners/snyk-scanner');
const SemgrepParser = require('./parsers/semgrep-parser');
const SnykParser = require('./parsers/snyk-parser');
const ResultNormalizer = require('./parsers/normalizer');
const ResultStorage = require('./database/storage');

/**
 * Main orchestrator - runs all security tools
 */

class MultiToolScanner {
  constructor() {
    this.semgrepScanner = new SemgrepScanner();
    this.snykScanner = new SnykScanner();
    this.semgrepParser = new SemgrepParser();
    this.snykParser = new SnykParser();
    this.normalizer = new ResultNormalizer();
    this.storage = null;
  }

  async initialize() {
    if (process.env.MONGODB_URI) {
      this.storage = new ResultStorage(process.env.MONGODB_URI);
      await this.storage.connect();
    }
  }

  async scanAll(repositoryPaths) {
    console.log('=== Multi-Tool Security Scanner ===\n');
    console.log(`Scanning ${repositoryPaths.length} repositories with multiple tools\n`);

    const allResults = {
      semgrep: [],
      snyk: [],
      normalized: [],
      stored: []
    };

    // Run Semgrep
    console.log('--- Running Semgrep ---');
    const semgrepResults = await this.semgrepScanner.scanMultiple(repositoryPaths);
    const semgrepParsed = this.semgrepParser.parseMultiple(semgrepResults);
    allResults.semgrep = semgrepParsed;
    console.log();

    // Run Snyk Code
    console.log('--- Running Snyk Code ---');
    const snykResults = await this.snykScanner.scanMultiple(repositoryPaths);
    const snykParsed = this.snykParser.parseMultiple(snykResults);
    allResults.snyk = snykParsed;
    console.log();

    // Normalize all results
    console.log('--- Normalizing Results ---');
    const normalizedSemgrep = this.normalizer.normalizeMultiple(semgrepParsed);
    const normalizedSnyk = this.normalizer.normalizeMultiple(snykParsed);
    allResults.normalized = [...normalizedSemgrep, ...normalizedSnyk];
    console.log(`Normalized ${allResults.normalized.length} analyses\n`);

    // Store in database
    if (this.storage) {
      console.log('--- Storing in Database ---');
      const storeResults = await this.storage.storeMultiple(allResults.normalized);
      allResults.stored = storeResults;
      console.log(`Stored ${storeResults.filter(r => r.success).length}/${storeResults.length} analyses\n`);
    }

    return allResults;
  }

  async cleanup() {
    if (this.storage) {
      await this.storage.disconnect();
    }
  }

  printSummary(results) {
    console.log('\n=== Scan Summary ===');
    
    const semgrepFindings = results.semgrep.reduce((sum, r) => sum + (r.stats?.total_findings || 0), 0);
    const snykFindings = results.snyk.reduce((sum, r) => sum + (r.stats?.total_findings || 0), 0);
    
    console.log(`\nSemgrep:     ${semgrepFindings} findings`);
    console.log(`Snyk Code:   ${snykFindings} findings`);
    console.log(`Total:       ${semgrepFindings + snykFindings} findings`);

    // Severity breakdown
    const allNormalized = results.normalized;
    const allAlerts = allNormalized.flatMap(r => r.alerts);
    
    const bySeverity = {
      critical: allAlerts.filter(a => a.security_severity === 'critical').length,
      high: allAlerts.filter(a => a.security_severity === 'high').length,
      medium: allAlerts.filter(a => a.security_severity === 'medium').length,
      low: allAlerts.filter(a => a.security_severity === 'low').length
    };
    
    console.log('\nBy Severity:');
    console.log(`  Critical: ${bySeverity.critical}`);
    console.log(`  High:     ${bySeverity.high}`);
    console.log(`  Medium:   ${bySeverity.medium}`);
    console.log(`  Low:      ${bySeverity.low}`);

    // By tool
    console.log('\nBy Tool:');
    const byTool = {};
    allNormalized.forEach(result => {
      byTool[result.tool_name] = (byTool[result.tool_name] || 0) + result.alerts.length;
    });
    Object.entries(byTool).forEach(([tool, count]) => {
      console.log(`  ${tool}: ${count}`);
    });
  }
}

// CLI usage
async function main() {
  const targetRepos = process.env.TARGET_REPOS?.split(',').map(r => r.trim()) || [];
  
  if (targetRepos.length === 0) {
    console.error('❌ No target repositories specified. Set TARGET_REPOS in .env');
    process.exit(1);
  }

  const scanner = new MultiToolScanner();
  
  try {
    await scanner.initialize();
    const results = await scanner.scanAll(targetRepos);
    scanner.printSummary(results);
    console.log('\n✅ Multi-tool scan complete!');
  } catch (error) {
    console.error('❌ Scan failed:', error);
    process.exit(1);
  } finally {
    await scanner.cleanup();
  }
}

if (require.main === module) {
  main();
}

module.exports = MultiToolScanner;

