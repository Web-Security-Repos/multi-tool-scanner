/**
 * Parse ESLint JSON output and normalize to common format
 */

class ESLintParser {
  
  /**
   * Map ESLint severity to normalized severity
   */
  normalizeSeverity(eslintSeverity, ruleId) {
    // ESLint severity: 1 = warning, 2 = error
    
    // Security-critical rules
    const criticalRules = [
      'security/detect-eval-with-expression',
      'security/detect-unsafe-regex',
      'security/detect-buffer-noassert',
      'security/detect-pseudoRandomBytes',
      'no-unsanitized/method',
      'no-unsanitized/property'
    ];
    
    if (criticalRules.includes(ruleId)) {
      return 'high';
    }
    
    return eslintSeverity === 2 ? 'high' : 'medium';
  }

  /**
   * Extract vulnerability category from rule ID
   */
  extractCategory(ruleId) {
    const categoryMap = {
      'eval': 'Code Injection',
      'child-process': 'Command Injection',
      'regex': 'ReDoS',
      'csrf': 'CSRF',
      'timing': 'Timing Attack',
      'crypto': 'Cryptography',
      'unsanitized': 'XSS',
      'object-injection': 'Injection',
      'require': 'Path Traversal'
    };

    for (const [key, value] of Object.entries(categoryMap)) {
      if (ruleId.toLowerCase().includes(key)) {
        return value;
      }
    }
    
    return 'Other';
  }

  /**
   * Parse a single ESLint message
   */
  parseMessage(message, filePath, repositoryName) {
    return {
      rule_id: message.ruleId,
      rule_description: this.getRuleDescription(message.ruleId),
      severity: this.normalizeSeverity(message.severity, message.ruleId),
      category: this.extractCategory(message.ruleId),
      message: message.message,
      location: {
        path: filePath,
        start_line: message.line,
        end_line: message.endLine || message.line,
        start_column: message.column,
        end_column: message.endColumn || message.column
      },
      code_snippet: null,
      confidence: 'HIGH',
      fix: message.fix ? 'available' : null
    };
  }

  /**
   * Get human-readable description for rule
   */
  getRuleDescription(ruleId) {
    const descriptions = {
      'security/detect-object-injection': 'Bracket object notation with user input is potentially unsafe',
      'security/detect-non-literal-regexp': 'RegExp constructed from non-literal input',
      'security/detect-unsafe-regex': 'Potentially unsafe regular expression (ReDoS)',
      'security/detect-buffer-noassert': 'Buffer allocation without proper assertion',
      'security/detect-child-process': 'Child process execution detected',
      'security/detect-disable-mustache-escape': 'Mustache escaping disabled',
      'security/detect-eval-with-expression': 'Eval with expression detected',
      'security/detect-no-csrf-before-method-override': 'CSRF middleware not before method override',
      'security/detect-non-literal-fs-filename': 'Non-literal filesystem path',
      'security/detect-non-literal-require': 'Non-literal require statement',
      'security/detect-possible-timing-attacks': 'Possible timing attack vulnerability',
      'security/detect-pseudoRandomBytes': 'Use of pseudo-random bytes for security',
      'no-unsanitized/method': 'Unsanitized method call (potential XSS)',
      'no-unsanitized/property': 'Unsanitized property assignment (potential XSS)'
    };
    
    return descriptions[ruleId] || ruleId;
  }

  /**
   * Parse full ESLint scan output
   */
  parse(scanOutput) {
    if (!scanOutput.success) {
      return {
        success: false,
        error: scanOutput.error,
        findings: []
      };
    }

    const rawResults = scanOutput.raw_output || [];
    const findings = [];

    rawResults.forEach(fileResult => {
      const relativePath = fileResult.filePath.replace(scanOutput.repository_path + '/', '');
      
      fileResult.messages.forEach(message => {
        findings.push(this.parseMessage(message, relativePath, scanOutput.repository));
      });
    });

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

module.exports = ESLintParser;

