const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

class SemgrepScanner {
  constructor() {
    this.name = 'Semgrep';
    this.version = this.getVersion();
  }

  getVersion() {
    try {
      const version = execSync('semgrep --version', { encoding: 'utf-8' });
      return version.trim();
    } catch (error) {
      console.error('Semgrep not found. Install with: pip install semgrep');
      return 'unknown';
    }
  }

  async scan(repositoryPath) {
    const startTime = Date.now();
    const repoName = path.basename(repositoryPath);
    
    console.log(`[Semgrep] Scanning ${repoName}...`);

    try {
      // Check if repository exists
      if (!fs.existsSync(repositoryPath)) {
        throw new Error(`Repository not found: ${repositoryPath}`);
      }

      // Run Semgrep with security rulesets
      const command = `semgrep --config=auto --json --quiet "${repositoryPath}"`;
      
      let output;
      try {
        output = execSync(command, { 
          encoding: 'utf-8',
          maxBuffer: 10 * 1024 * 1024,
          stdio: ['pipe', 'pipe', 'pipe']
        });
      } catch (error) {
        // Semgrep returns non-zero exit code when findings exist
        if (error.stdout) {
          output = error.stdout;
        } else {
          throw error;
        }
      }

      const results = JSON.parse(output);
      const scanDuration = Date.now() - startTime;

      console.log(`[Semgrep] Found ${results.results?.length || 0} findings in ${scanDuration}ms`);

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
      console.error(`[Semgrep] Error scanning ${repoName}:`, error.message);
      
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

module.exports = SemgrepScanner;

// CLI usage
if (require.main === module) {
  const scanner = new SemgrepScanner();
  const targetRepos = process.env.TARGET_REPOS?.split(',') || [];
  
  if (targetRepos.length === 0) {
    console.error('No target repositories specified. Set TARGET_REPOS in .env');
    process.exit(1);
  }

  scanner.scanMultiple(targetRepos)
    .then(results => {
      console.log('\n=== Semgrep Scan Complete ===');
      console.log(JSON.stringify(results, null, 2));
    })
    .catch(error => {
      console.error('Scan failed:', error);
      process.exit(1);
    });
}

