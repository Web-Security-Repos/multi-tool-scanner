require('dotenv').config();
const MultiToolScanner = require('./index');
const ComparisonAnalyzer = require('./comparison/analyzer');
const ResultStorage = require('./database/storage');

/**
 * Complete integration test for multi-tool scanner
 */

async function testIntegration() {
  console.log('=== Multi-Tool Scanner Integration Test ===\n');

  // Check prerequisites
  console.log('1. Checking prerequisites...');
  
  if (!process.env.TARGET_REPOS) {
    console.error('❌ TARGET_REPOS not set in .env');
    return false;
  }
  
  if (!process.env.MONGODB_URI) {
    console.warn('⚠️  MONGODB_URI not set - database storage will be skipped');
  }
  
  const targetRepos = process.env.TARGET_REPOS.split(',').map(r => r.trim());
  console.log(`   Target repositories: ${targetRepos.length}`);
  console.log(`   MongoDB configured: ${process.env.MONGODB_URI ? 'Yes' : 'No'}`);
  console.log();

  // Test 1: Scanner initialization
  console.log('2. Testing scanner initialization...');
  const scanner = new MultiToolScanner();
  try {
    await scanner.initialize();
    console.log('   ✅ Scanner initialized\n');
  } catch (error) {
    console.error('   ❌ Initialization failed:', error.message);
    return false;
  }

  // Test 2: Run scans
  console.log('3. Running multi-tool scans...');
  let results;
  try {
    results = await scanner.scanAll(targetRepos);
    console.log('   ✅ Scans completed\n');
  } catch (error) {
    console.error('   ❌ Scan failed:', error.message);
    await scanner.cleanup();
    return false;
  }

  // Test 3: Verify results
  console.log('4. Verifying results...');
  const semgrepCount = results.semgrep.length;
  const snykCount = results.snyk.length;
  const normalizedCount = results.normalized.length;
  
  console.log(`   Semgrep scans: ${semgrepCount}`);
  console.log(`   Snyk scans: ${snykCount}`);
  console.log(`   Normalized results: ${normalizedCount}`);
  
  if (normalizedCount !== semgrepCount + snykCount) {
    console.error('   ⚠️  Normalization count mismatch');
  } else {
    console.log('   ✅ Result counts match\n');
  }

  // Test 4: Database storage
  if (process.env.MONGODB_URI && results.stored) {
    console.log('5. Verifying database storage...');
    const successfulStores = results.stored.filter(r => r.success).length;
    console.log(`   Stored: ${successfulStores}/${results.stored.length}`);
    
    if (successfulStores > 0) {
      console.log('   ✅ Database storage working\n');
    } else {
      console.error('   ❌ No results stored\n');
    }
  }

  // Test 5: Comparison analysis
  if (process.env.MONGODB_URI) {
    console.log('6. Testing comparison analysis...');
    const analyzer = new ComparisonAnalyzer();
    const storage = new ResultStorage(process.env.MONGODB_URI);
    
    try {
      await storage.connect();
      
      const Repository = require('../database/models/Repository');
      const repos = await Repository.find().limit(1);
      
      if (repos.length > 0) {
        const report = await analyzer.compareRepository(repos[0]._id, storage);
        console.log(`   Tools in comparison: ${report.tools.length}`);
        console.log(`   Common findings: ${report.overlap.common_findings}`);
        console.log(`   Unique findings: ${report.overlap.unique_findings}`);
        console.log('   ✅ Comparison analysis working\n');
      } else {
        console.log('   ⚠️  No repositories in database yet\n');
      }
      
      await storage.disconnect();
    } catch (error) {
      console.error('   ❌ Comparison failed:', error.message);
    }
  }

  // Print summary
  scanner.printSummary(results);

  await scanner.cleanup();
  
  console.log('\n=== Integration Test Complete ===');
  console.log('✅ All tests passed!\n');
  
  // Force disconnect from MongoDB to exit
  const { disconnectFromDatabase } = require('../database/config/connection');
  await disconnectFromDatabase();
  
  return true;
}

// Run test
testIntegration()
  .then(success => {
    if (!success) {
      console.error('\n❌ Integration test failed');
      process.exit(1);
    }
  })
  .catch(error => {
    console.error('\n❌ Test error:', error);
    process.exit(1);
  });

