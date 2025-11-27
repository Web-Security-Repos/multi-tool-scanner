const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

/**
 * Snyk Code Scanner
 * Uses Snyk CLI for static code analysis
 */

class SnykScanner {
  constructor() {
    this.name = 'Snyk Code';
    this.version = this.getVersion();
  }

  getVersion() {
    try {
      const version = execSync('snyk version', { encoding: 'utf-8' });
      return version.trim();
    } catch (error) {
      console.error('Snyk not found. Install with: npm install -g snyk');
      return 'unknown';
    }
  }

  async scan(repositoryPath) {
    const startTime = Date.now();
    const repoName = path.basename(repositoryPath);
    
    console.log(`[Snyk] Scanning ${repoName}...`);

    try {
      // Check if repository exists
      if (!fs.existsSync(repositoryPath)) {
        throw new Error(`Repository not found: ${repositoryPath}`);
      }

      // Run Snyk Code test (SAST)
      // --json for JSON output
      // --severity-threshold=low to get all findings
      // --exclude to skip node_modules
      const command = `snyk code test "${repositoryPath}" --json --exclude=node_modules`;
      
      let output;
      try {
        output = execSync(command, { 
          encoding: 'utf-8',
          maxBuffer: 10 * 1024 * 1024,
          stdio: ['pipe', 'pipe', 'pipe']
        });
      } catch (error) {
        // Snyk returns non-zero exit code when findings exist
        if (error.stdout) {
          output = error.stdout;
        } else if (error.message.includes('Not authenticated')) {
          throw new Error('Snyk not authenticated. Run: snyk auth');
        } else {
          throw error;
        }
      }

      const results = JSON.parse(output);
      const scanDuration = Date.now() - startTime;

      const findingsCount = results.runs?.[0]?.results?.length || 0;
      console.log(`[Snyk] Found ${findingsCount} findings in ${scanDuration}ms`);

      return {
        tool_name: this.name,
        tool_version: this.version,
        repository: repoName,
        repository_path: repositoryPath,
        scan_date: new Date().toISOString(),
        scan_duration_ms: scanDuration,
        raw_output: results,
        success: true
      };

    } catch (error) {
      console.error(`[Snyk] Error scanning ${repoName}:`, error.message);
      
      return {
        tool_name: this.name,
        tool_version: this.version,
        repository: repoName,
        repository_path: repositoryPath,
        scan_date: new Date().toISOString(),
        scan_duration_ms: Date.now() - startTime,
        error: error.message,
        success: false
      };
    }
  }

  async scanMultiple(repositoryPaths) {
    const results = [];
    
    for (const repoPath of repositoryPaths) {
      const result = await this.scan(repoPath);
      results.push(result);
      
      // Small delay between scans
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    return results;
  }
}

module.exports = SnykScanner;

// CLI usage
if (require.main === module) {
  require('dotenv').config();
  
  const scanner = new SnykScanner();
  const targetRepos = process.env.TARGET_REPOS?.split(',').map(r => r.trim()) || [];
  
  if (targetRepos.length === 0) {
    console.error('No target repositories specified. Set TARGET_REPOS in .env');
    process.exit(1);
  }

  scanner.scanMultiple(targetRepos)
    .then(results => {
      console.log('\n=== Snyk Code Scan Complete ===');
      console.log(JSON.stringify(results, null, 2));
    })
    .catch(error => {
      console.error('Scan failed:', error);
      process.exit(1);
    });
}

