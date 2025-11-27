const { ESLint } = require('eslint');
const fs = require('fs');
const path = require('path');

/**
 * ESLint Security Scanner
 * Uses eslint-plugin-security and eslint-plugin-no-unsanitized
 */

class ESLintScanner {
  constructor() {
    this.name = 'ESLint-Security';
    this.version = this.getVersion();
    this.configPath = path.join(__dirname, '../config/eslint-security.json');
  }

  getVersion() {
    try {
      const eslintPackage = require('eslint/package.json');
      return eslintPackage.version;
    } catch (error) {
      return 'unknown';
    }
  }

  async scan(repositoryPath) {
    const startTime = Date.now();
    const repoName = path.basename(repositoryPath);
    
    console.log(`[ESLint] Scanning ${repoName}...`);

    try {
      // Check if repository exists
      if (!fs.existsSync(repositoryPath)) {
        throw new Error(`Repository not found: ${repositoryPath}`);
      }

      // Load ESLint configuration
      const configData = JSON.parse(fs.readFileSync(this.configPath, 'utf-8'));
      
      // Create ESLint instance
      const eslint = new ESLint({
        overrideConfig: configData,
        overrideConfigFile: true,
        ignore: true
      });

      // Find JavaScript files to scan
      const filesToScan = await this.findJavaScriptFiles(repositoryPath);
      
      if (filesToScan.length === 0) {
        console.log(`[ESLint] No JavaScript files found in ${repoName}`);
        return {
          tool_name: this.name,
          tool_version: this.version,
          repository: repoName,
          repository_path: repositoryPath,
          scan_date: new Date().toISOString(),
          scan_duration_ms: Date.now() - startTime,
          raw_output: [],
          success: true
        };
      }

      console.log(`[ESLint] Found ${filesToScan.length} JavaScript files`);

      // Run ESLint
      const results = await eslint.lintFiles(filesToScan);
      
      // Filter to only security issues
      const securityResults = results.map(result => ({
        ...result,
        messages: result.messages.filter(msg => 
          msg.ruleId && 
          (msg.ruleId.startsWith('security/') || msg.ruleId.startsWith('no-unsanitized/'))
        )
      })).filter(result => result.messages.length > 0);

      const totalIssues = securityResults.reduce((sum, r) => sum + r.messages.length, 0);
      const scanDuration = Date.now() - startTime;

      console.log(`[ESLint] Found ${totalIssues} security issues in ${scanDuration}ms`);

      return {
        tool_name: this.name,
        tool_version: this.version,
        repository: repoName,
        repository_path: repositoryPath,
        scan_date: new Date().toISOString(),
        scan_duration_ms: scanDuration,
        raw_output: securityResults,
        success: true
      };

    } catch (error) {
      console.error(`[ESLint] Error scanning ${repoName}:`, error.message);
      
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

  /**
   * Find all JavaScript files in directory (recursively)
   */
  async findJavaScriptFiles(dir, fileList = []) {
    const files = fs.readdirSync(dir);
    
    for (const file of files) {
      const filePath = path.join(dir, file);
      const stat = fs.statSync(filePath);
      
      if (stat.isDirectory()) {
        // Skip node_modules and other common directories
        if (!['node_modules', '.git', 'dist', 'build', 'coverage'].includes(file)) {
          await this.findJavaScriptFiles(filePath, fileList);
        }
      } else if (stat.isFile()) {
        // Include .js, .jsx, .mjs files
        if (/\.(js|jsx|mjs)$/.test(file) && !file.endsWith('.test.js') && !file.endsWith('.spec.js')) {
          fileList.push(filePath);
        }
      }
    }
    
    return fileList;
  }

  async scanMultiple(repositoryPaths) {
    const results = [];
    
    for (const repoPath of repositoryPaths) {
      const result = await this.scan(repoPath);
      results.push(result);
      
      // Small delay between scans
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    
    return results;
  }
}

module.exports = ESLintScanner;

// CLI usage
if (require.main === module) {
  require('dotenv').config();
  
  const scanner = new ESLintScanner();
  const targetRepos = process.env.TARGET_REPOS?.split(',').map(r => r.trim()) || [];
  
  if (targetRepos.length === 0) {
    console.error('No target repositories specified. Set TARGET_REPOS in .env');
    process.exit(1);
  }

  scanner.scanMultiple(targetRepos)
    .then(results => {
      console.log('\n=== ESLint Security Scan Complete ===');
      console.log(JSON.stringify(results, null, 2));
    })
    .catch(error => {
      console.error('Scan failed:', error);
      process.exit(1);
    });
}

