/**
 * Parse Snyk Code JSON output and normalize to common format
 * Snyk uses SARIF format
 */

class SnykParser {
  
  /**
   * Map Snyk severity to normalized severity
   */
  normalizeSeverity(snykSeverity) {
    const severityMap = {
      'error': 'high',
      'warning': 'medium',
      'note': 'low',
      'high': 'high',
      'medium': 'medium',
      'low': 'low'
    };
    
    return severityMap[snykSeverity?.toLowerCase()] || 'medium';
  }

  /**
   * Extract vulnerability category from rule ID
   */
  extractCategory(ruleId, message) {
    const categories = {
      'sql': 'SQL Injection',
      'xss': 'XSS',
      'injection': 'Code Injection',
      'command': 'Command Injection',
      'path': 'Path Traversal',
      'traversal': 'Path Traversal',
      'ssrf': 'SSRF',
      'csrf': 'CSRF',
      'hardcoded': 'Hardcoded Credentials',
      'password': 'Hardcoded Credentials',
      'secret': 'Hardcoded Credentials',
      'deserialization': 'Insecure Deserialization',
      'crypto': 'Cryptography',
      'auth': 'Auth Flaws',
      'session': 'Session Management',
      'redirect': 'Open Redirect'
    };

    const lowerRuleId = ruleId.toLowerCase();
    const lowerMessage = message.toLowerCase();
    
    for (const [key, value] of Object.entries(categories)) {
      if (lowerRuleId.includes(key) || lowerMessage.includes(key)) {
        return value;
      }
    }
    
    return 'Other';
  }

  /**
   * Parse a single Snyk result (SARIF format)
   */
  parseResult(result, repositoryName, repositoryPath) {
    const rule = result.ruleId || 'unknown';
    const message = result.message?.text || 'Security issue detected';
    const level = result.level || 'warning';
    
    const location = result.locations?.[0]?.physicalLocation;
    const filePath = location?.artifactLocation?.uri || '';
    const region = location?.region;

    return {
      rule_id: rule,
      rule_description: message,
      severity: this.normalizeSeverity(level),
      category: this.extractCategory(rule, message),
      message: message,
      location: {
        path: filePath.replace(repositoryPath + '/', ''),
        start_line: region?.startLine || null,
        end_line: region?.endLine || region?.startLine || null,
        start_column: region?.startColumn || null,
        end_column: region?.endColumn || null
      },
      code_snippet: region?.snippet?.text || null,
      confidence: 'HIGH',
      cwe: result.properties?.cwe || [],
      references: result.properties?.references || []
    };
  }

  /**
   * Parse full Snyk scan output
   */
  parse(scanOutput) {
    if (!scanOutput.success) {
      return {
        success: false,
        error: scanOutput.error,
        findings: []
      };
    }

    // Snyk uses SARIF format
    const rawResults = scanOutput.raw_output?.runs?.[0]?.results || [];
    const findings = rawResults.map(result => 
      this.parseResult(result, scanOutput.repository, scanOutput.repository_path)
    );

    // Calculate statistics
    const stats = {
      total_findings: findings.length,
      by_severity: {
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length
      },
      by_category: {}
    };

    // Count by category
    findings.forEach(finding => {
      stats.by_category[finding.category] = (stats.by_category[finding.category] || 0) + 1;
    });

    return {
      tool_name: scanOutput.tool_name,
      tool_version: scanOutput.tool_version,
      repository: scanOutput.repository,
      repository_path: scanOutput.repository_path,
      scan_date: scanOutput.scan_date,
      scan_duration_ms: scanOutput.scan_duration_ms,
      findings: findings,
      stats: stats,
      success: true
    };
  }

  /**
   * Parse multiple scan outputs
   */
  parseMultiple(scanOutputs) {
    return scanOutputs.map(output => this.parse(output));
  }
}

module.exports = SnykParser;

