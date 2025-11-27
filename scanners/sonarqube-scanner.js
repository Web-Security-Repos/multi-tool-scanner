const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

/**
 * SonarQube Scanner
 * Uses SonarScanner CLI with SonarCloud or local SonarQube
 */

class SonarQubeScanner {
  constructor() {
    this.name = 'SonarQube';
    this.version = this.getVersion();
  }

  getVersion() {
    try {
      const version = execSync('sonar-scanner --version', { encoding: 'utf-8' });
      return version.trim().split('\n')[0];
    } catch (error) {
      console.error('SonarScanner not found. Install from: https://docs.sonarcloud.io/advanced-setup/ci-based-analysis/sonarscanner-cli/');
      return 'unknown';
    }
  }

  async scan(repositoryPath) {
    const startTime = Date.now();
    const repoName = path.basename(repositoryPath);
    
    console.log(`[SonarQube] Scanning ${repoName}...`);

    try {
      // Check if repository exists
      if (!fs.existsSync(repositoryPath)) {
        throw new Error(`Repository not found: ${repositoryPath}`);
      }

      // Check for required environment variables
      if (!process.env.SONAR_TOKEN) {
        throw new Error('SONAR_TOKEN not set in .env. Get token from: https://sonarcloud.io/account/security');
      }

      const projectKey = `websec-${repoName}`;
      const sonarHost = process.env.SONAR_HOST_URL || 'https://sonarcloud.io';
      const sonarOrg = process.env.SONAR_ORGANIZATION || '';

      // Create temporary sonar-project.properties
      const propsPath = path.join(repositoryPath, 'sonar-project.properties');
      const propsContent = `
sonar.projectKey=${projectKey}
sonar.projectName=${repoName}
sonar.sources=.
sonar.host.url=${sonarHost}
${sonarOrg ? `sonar.organization=${sonarOrg}` : ''}
sonar.sourceEncoding=UTF-8
sonar.exclusions=**/node_modules/**,**/test/**,**/*.test.js
      `.trim();
      
      fs.writeFileSync(propsPath, propsContent);

      // Run SonarScanner
      const command = `cd "${repositoryPath}" && sonar-scanner -Dsonar.login=${process.env.SONAR_TOKEN}`;
      
      let output;
      try {
        output = execSync(command, { 
          encoding: 'utf-8',
          maxBuffer: 10 * 1024 * 1024,
          stdio: ['pipe', 'pipe', 'pipe']
        });
      } catch (error) {
        if (error.stdout) {
          output = error.stdout;
        } else {
          // Clean up
          fs.unlinkSync(propsPath);
          throw error;
        }
      }

      // Clean up properties file
      fs.unlinkSync(propsPath);

      // Wait a bit for SonarCloud to process
      console.log(`[SonarQube] Waiting for analysis to complete...`);
      await new Promise(resolve => setTimeout(resolve, 5000));

      // Fetch results from SonarQube API
      const results = await this.fetchResults(projectKey, sonarHost);
      
      const scanDuration = Date.now() - startTime;
      console.log(`[SonarQube] Found ${results.issues?.length || 0} findings in ${scanDuration}ms`);

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
      console.error(`[SonarQube] Error scanning ${repoName}:`, error.message);
      
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

  async fetchResults(projectKey, sonarHost) {
    try {
      const fetch = require('node-fetch');
      const token = Buffer.from(`${process.env.SONAR_TOKEN}:`).toString('base64');
      
      const url = `${sonarHost}/api/issues/search?componentKeys=${projectKey}&types=VULNERABILITY,SECURITY_HOTSPOT&ps=500`;
      
      const response = await fetch(url, {
        headers: {
          'Authorization': `Basic ${token}`
        }
      });

      if (!response.ok) {
        console.warn(`[SonarQube] API fetch failed: ${response.statusText}`);
        return { issues: [] };
      }

      const data = await response.json();
      return data;
      
    } catch (error) {
      console.warn(`[SonarQube] Could not fetch results from API:`, error.message);
      return { issues: [] };
    }
  }

  async scanMultiple(repositoryPaths) {
    const results = [];
    
    for (const repoPath of repositoryPaths) {
      const result = await this.scan(repoPath);
      results.push(result);
      
      // Delay between scans
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
    
    return results;
  }
}

module.exports = SonarQubeScanner;

// CLI usage
if (require.main === module) {
  require('dotenv').config();
  
  const scanner = new SonarQubeScanner();
  const targetRepos = process.env.TARGET_REPOS?.split(',').map(r => r.trim()) || [];
  
  if (targetRepos.length === 0) {
    console.error('No target repositories specified. Set TARGET_REPOS in .env');
    process.exit(1);
  }

  scanner.scanMultiple(targetRepos)
    .then(results => {
      console.log('\n=== SonarQube Scan Complete ===');
      console.log(JSON.stringify(results, null, 2));
    })
    .catch(error => {
      console.error('Scan failed:', error);
      process.exit(1);
    });
}

