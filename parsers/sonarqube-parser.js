/**
 * Parse SonarQube JSON output and normalize to common format
 */

class SonarQubeParser {
  
  /**
   * Map SonarQube severity to normalized severity
   */
  normalizeSeverity(sonarSeverity) {
    const severityMap = {
      'BLOCKER': 'critical',
      'CRITICAL': 'critical',
      'MAJOR': 'high',
      'MINOR': 'medium',
      'INFO': 'low'
    };
    
    return severityMap[sonarSeverity?.toUpperCase()] || 'medium';
  }

  /**
   * Extract vulnerability category from rule
   */
  extractCategory(rule, message) {
    const categories = {
      'sql': 'SQL Injection',
      'xss': 'XSS',
      'injection': 'Code Injection',
      'command': 'Command Injection',
      'path': 'Path Traversal',
      'traversal': 'Path Traversal',
      'ssrf': 'SSRF',
      'csrf': 'CSRF',
      'password': 'Hardcoded Credentials',
      'secret': 'Hardcoded Credentials',
      'hardcoded': 'Hardcoded Credentials',
      'deserialization': 'Insecure Deserialization',
      'crypto': 'Cryptography',
      'auth': 'Auth Flaws',
      'session': 'Session Management',
      'redirect': 'Open Redirect',
      'xxe': 'XXE',
      'ldap': 'LDAP Injection'
    };

    const lowerRule = rule.toLowerCase();
    const lowerMessage = message.toLowerCase();
    
    for (const [key, value] of Object.entries(categories)) {
      if (lowerRule.includes(key) || lowerMessage.includes(key)) {
        return value;
      }
    }
    
    return 'Other';
  }

  /**
   * Parse a single SonarQube issue
   */
  parseIssue(issue, repositoryName) {
    const rule = issue.rule || 'unknown';
    const message = issue.message || 'Security issue detected';
    const severity = issue.severity || 'MAJOR';

    return {
      rule_id: rule,
      rule_description: message,
      severity: this.normalizeSeverity(severity),
      category: this.extractCategory(rule, message),
      message: message,
      location: {
        path: issue.component?.replace(/.*:/, '') || '',
        start_line: issue.line || issue.textRange?.startLine || null,
        end_line: issue.textRange?.endLine || issue.line || null,
        start_column: issue.textRange?.startOffset || null,
        end_column: issue.textRange?.endOffset || null
      },
      code_snippet: null,
      confidence: issue.type === 'VULNERABILITY' ? 'HIGH' : 'MEDIUM',
      effort: issue.effort || null,
      status: issue.status || 'OPEN'
    };
  }

  /**
   * Parse full SonarQube scan output
   */
  parse(scanOutput) {
    if (!scanOutput.success) {
      return {
        success: false,
        error: scanOutput.error,
        findings: []
      };
    }

    const rawIssues = scanOutput.raw_output?.issues || [];
    const findings = rawIssues.map(issue => 
      this.parseIssue(issue, scanOutput.repository)
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

module.exports = SonarQubeParser;

