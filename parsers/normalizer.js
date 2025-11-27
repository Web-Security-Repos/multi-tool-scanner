/**
 * Normalize results from different tools to a common format
 * This format matches the database schema for Analysis and Alert models
 */

class ResultNormalizer {
  
  /**
   * Normalize a finding to match the Alert schema
   */
  normalizeAlert(finding, toolName) {
    return {
      tool_name: toolName,
      rule_id: finding.rule_id,
      rule_description: finding.rule_description || finding.message,
      severity: this.mapSeverityToCodeQL(finding.severity),
      security_severity: finding.severity, // critical/high/medium/low
      state: 'open',
      location: {
        path: finding.location.path,
        start_line: finding.location.start_line,
        end_line: finding.location.end_line,
        start_column: finding.location.start_column,
        end_column: finding.location.end_column
      },
      message: finding.message,
      category: finding.category || 'Other',
      metadata: {
        confidence: finding.confidence,
        cwe: finding.cwe,
        owasp: finding.owasp,
        references: finding.references,
        code_snippet: finding.code_snippet
      }
    };
  }

  /**
   * Map normalized severity to CodeQL severity format
   */
  mapSeverityToCodeQL(severity) {
    const severityMap = {
      'critical': 'error',
      'high': 'error',
      'medium': 'warning',
      'low': 'note'
    };
    
    return severityMap[severity] || 'warning';
  }

  /**
   * Normalize an analysis to match the Analysis schema
   */
  normalizeAnalysis(parsedResult) {
    return {
      tool_name: parsedResult.tool_name,
      tool_version: parsedResult.tool_version,
      repository: parsedResult.repository,
      scan_date: parsedResult.scan_date,
      scan_duration_ms: parsedResult.scan_duration_ms,
      results_count: parsedResult.stats?.total_findings || 0,
      stats: parsedResult.stats,
      alerts: parsedResult.findings.map(finding => 
        this.normalizeAlert(finding, parsedResult.tool_name)
      )
    };
  }

  /**
   * Normalize multiple parsed results
   */
  normalizeMultiple(parsedResults) {
    return parsedResults.map(result => this.normalizeAnalysis(result));
  }

  /**
   * Create a unique fingerprint for a finding to detect duplicates
   */
  createFingerprint(alert) {
    const components = [
      alert.rule_id,
      alert.location.path,
      alert.location.start_line,
      alert.category
    ];
    
    return components.join('::');
  }

  /**
   * Compare findings from different tools
   */
  compareFindings(normalizedResults) {
    const findingsByRepo = {};
    
    // Group findings by repository
    normalizedResults.forEach(result => {
      const repoName = result.repository;
      
      if (!findingsByRepo[repoName]) {
        findingsByRepo[repoName] = {};
      }
      
      // Store findings by tool
      findingsByRepo[repoName][result.tool_name] = result.alerts.map(alert => ({
        ...alert,
        fingerprint: this.createFingerprint(alert)
      }));
    });
    
    return findingsByRepo;
  }
}

module.exports = ResultNormalizer;

