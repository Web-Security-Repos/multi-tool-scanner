require('dotenv').config();
const SemgrepScanner = require('./scanners/semgrep-scanner');
const SemgrepParser = require('./parsers/semgrep-parser');
const ResultNormalizer = require('./parsers/normalizer');
const ResultStorage = require('./database/storage');

/**
 * Test script for Semgrep integration
 */

async function testSemgrepIntegration() {
  console.log('=== Testing Semgrep Integration ===\n');

  // Step 1: Initialize scanner
  console.log('1. Initializing Semgrep scanner...');
  const scanner = new SemgrepScanner();
  console.log(`   Version: ${scanner.version}\n`);

  // Step 2: Get target repositories
  const targetRepos = process.env.TARGET_REPOS?.split(',').map(r => r.trim()) || [];
  
  if (targetRepos.length === 0) {
    console.error('❌ No target repositories found. Set TARGET_REPOS in .env');
    process.exit(1);
  }

  console.log(`2. Target repositories (${targetRepos.length}):`);
  targetRepos.forEach(repo => console.log(`   - ${repo}`));
  console.log();

  // Step 3: Scan repositories
  console.log('3. Running Semgrep scans...');
  const scanResults = await scanner.scanMultiple(targetRepos);
  const successfulScans = scanResults.filter(r => r.success);
  console.log(`   Completed: ${successfulScans.length}/${scanResults.length} successful\n`);

  // Step 4: Parse results
  console.log('4. Parsing scan results...');
  const parser = new SemgrepParser();
  const parsedResults = parser.parseMultiple(scanResults);
  console.log(`   Parsed ${parsedResults.length} results\n`);

  // Step 5: Normalize results
  console.log('5. Normalizing results...');
  const normalizer = new ResultNormalizer();
  const normalizedResults = normalizer.normalizeMultiple(parsedResults);
  
  let totalFindings = 0;
  normalizedResults.forEach(result => {
    totalFindings += result.alerts.length;
    console.log(`   - ${result.repository}: ${result.alerts.length} findings`);
  });
  console.log(`   Total findings: ${totalFindings}\n`);

  // Step 6: Store in database (if MongoDB configured)
  if (process.env.MONGODB_URI) {
    console.log('6. Storing results in MongoDB...');
    const storage = new ResultStorage(process.env.MONGODB_URI);
    
    try {
      await storage.connect();
      const storeResults = await storage.storeMultiple(normalizedResults);
      
      const successful = storeResults.filter(r => r.success).length;
      console.log(`   Stored: ${successful}/${storeResults.length} analyses\n`);
      
      await storage.disconnect();
    } catch (error) {
      console.error(`   ❌ Storage failed: ${error.message}\n`);
    }
  } else {
    console.log('6. Skipping database storage (MONGODB_URI not configured)\n');
  }

  // Summary
  console.log('=== Test Summary ===');
  console.log(`Scans completed: ${successfulScans.length}`);
  console.log(`Total findings: ${totalFindings}`);
  console.log(`By severity:`);
  
  const allFindings = normalizedResults.flatMap(r => r.alerts);
  const bySeverity = {
    critical: allFindings.filter(f => f.security_severity === 'critical').length,
    high: allFindings.filter(f => f.security_severity === 'high').length,
    medium: allFindings.filter(f => f.security_severity === 'medium').length,
    low: allFindings.filter(f => f.security_severity === 'low').length
  };
  
  console.log(`  Critical: ${bySeverity.critical}`);
  console.log(`  High: ${bySeverity.high}`);
  console.log(`  Medium: ${bySeverity.medium}`);
  console.log(`  Low: ${bySeverity.low}`);
  
  console.log('\n✅ Semgrep integration test complete!');
}

// Run test
testSemgrepIntegration().catch(error => {
  console.error('❌ Test failed:', error);
  process.exit(1);
});

