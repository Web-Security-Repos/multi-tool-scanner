/**
 * Parse Semgrep JSON output and normalize to common format
 */

class SemgrepParser {
  
  /**
   * Map Semgrep severity to normalized severity
   */
  normalizeSeverity(semgrepSeverity) {
    const severityMap = {
      'ERROR': 'critical',
      'WARNING': 'high',
      'INFO': 'medium'
    };
    
    return severityMap[semgrepSeverity?.toUpperCase()] || 'medium';
  }

  /**
   * Extract vulnerability category from rule ID
   */
  extractCategory(ruleId) {
    const categories = {
      'xss': 'XSS',
      'sql-injection': 'SQL Injection',
      'sqli': 'SQL Injection',
      'command-injection': 'Command Injection',
      'path-traversal': 'Path Traversal',
      'ssrf': 'SSRF',
      'csrf': 'CSRF',
      'hardcoded': 'Hardcoded Credentials',
      'deserialization': 'Insecure Deserialization',
      'auth': 'Auth Flaws',
      'crypto': 'Cryptography',
      'regex': 'ReDoS'
    };

    const lowerRuleId = ruleId.toLowerCase();
    
    for (const [key, value] of Object.entries(categories)) {
      if (lowerRuleId.includes(key)) {
        return value;
      }
    }
    
    return 'Other';
  }

  /**
   * Parse a single Semgrep result
   */
  parseResult(result, repositoryName) {
    return {
      rule_id: result.check_id,
      rule_description: result.extra?.message || result.extra?.metadata?.shortDescription || null,
      severity: this.normalizeSeverity(result.extra?.severity),
      category: this.extractCategory(result.check_id),
      message: result.extra?.message || 'Security issue detected',
      location: {
        path: result.path,
        start_line: result.start?.line || null,
        end_line: result.end?.line || null,
        start_column: result.start?.col || null,
        end_column: result.end?.col || null
      },
      code_snippet: result.extra?.lines || null,
      confidence: result.extra?.metadata?.confidence || 'MEDIUM',
      cwe: result.extra?.metadata?.cwe || [],
      owasp: result.extra?.metadata?.owasp || [],
      references: result.extra?.metadata?.references || []
    };
  }

  /**
   * Parse full Semgrep scan output
   */
  parse(scanOutput) {
    if (!scanOutput.success) {
      return {
        success: false,
        error: scanOutput.error,
        findings: []
      };
    }

    const rawResults = scanOutput.raw_output?.results || [];
    const findings = rawResults.map(result => 
      this.parseResult(result, scanOutput.repository)
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

module.exports = SemgrepParser;

