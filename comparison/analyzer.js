require('dotenv').config();
const ResultNormalizer = require('../parsers/normalizer');
const ResultStorage = require('../database/storage');

/**
 * Compare results from multiple security tools
 * Find overlaps, unique detections, and analyze effectiveness
 */

class ComparisonAnalyzer {
  constructor() {
    this.normalizer = new ResultNormalizer();
  }

  /**
   * Find common findings detected by multiple tools
   */
  findOverlap(toolResults) {
    const fingerprints = {};
    
    // Group findings by fingerprint
    Object.entries(toolResults).forEach(([toolName, alerts]) => {
      alerts.forEach(alert => {
        const fp = this.normalizer.createFingerprint(alert);
        
        if (!fingerprints[fp]) {
          fingerprints[fp] = {
            fingerprint: fp,
            alert: alert,
            detectedBy: []
          };
        }
        
        fingerprints[fp].detectedBy.push(toolName);
      });
    });
    
    // Find findings detected by multiple tools
    const overlap = Object.values(fingerprints).filter(f => f.detectedBy.length > 1);
    const unique = Object.values(fingerprints).filter(f => f.detectedBy.length === 1);
    
    return {
      overlap: overlap,
      unique: unique,
      total: Object.keys(fingerprints).length
    };
  }

  /**
   * Calculate tool effectiveness metrics
   */
  calculateEffectiveness(toolResults, overlapData) {
    const metrics = {};
    
    Object.entries(toolResults).forEach(([toolName, alerts]) => {
      const totalDetections = alerts.length;
      const uniqueDetections = overlapData.unique.filter(
        u => u.detectedBy[0] === toolName
      ).length;
      const sharedDetections = overlapData.overlap.filter(
        o => o.detectedBy.includes(toolName)
      ).length;
      
      metrics[toolName] = {
        total_detections: totalDetections,
        unique_detections: uniqueDetections,
        shared_detections: sharedDetections,
        uniqueness_rate: totalDetections > 0 ? (uniqueDetections / totalDetections * 100).toFixed(2) : 0
      };
    });
    
    return metrics;
  }

  /**
   * Analyze findings by severity across tools
   */
  analyzeBySeverity(toolResults) {
    const bySeverity = {};
    
    Object.entries(toolResults).forEach(([toolName, alerts]) => {
      bySeverity[toolName] = {
        critical: alerts.filter(a => a.security_severity === 'critical').length,
        high: alerts.filter(a => a.security_severity === 'high').length,
        medium: alerts.filter(a => a.security_severity === 'medium').length,
        low: alerts.filter(a => a.security_severity === 'low').length
      };
    });
    
    return bySeverity;
  }

  /**
   * Analyze findings by category across tools
   */
  analyzeByCategory(toolResults) {
    const byCategory = {};
    
    Object.entries(toolResults).forEach(([toolName, alerts]) => {
      byCategory[toolName] = {};
      
      alerts.forEach(alert => {
        const category = alert.category || 'Other';
        byCategory[toolName][category] = (byCategory[toolName][category] || 0) + 1;
      });
    });
    
    return byCategory;
  }

  /**
   * Generate comparison report for a repository
   */
  async compareRepository(repositoryId, storage) {
    const toolResults = await storage.getToolComparison(repositoryId);
    
    // Prepare normalized data
    const normalizedResults = {};
    Object.entries(toolResults).forEach(([toolName, alerts]) => {
      normalizedResults[toolName] = alerts.map(alert => ({
        rule_id: alert.rule_id,
        security_severity: alert.security_severity,
        category: this.extractCategory(alert),
        location: alert.location,
        fingerprint: this.normalizer.createFingerprint(alert)
      }));
    });
    
    // Analyze
    const overlapData = this.findOverlap(normalizedResults);
    const effectiveness = this.calculateEffectiveness(normalizedResults, overlapData);
    const bySeverity = this.analyzeBySeverity(normalizedResults);
    const byCategory = this.analyzeByCategory(normalizedResults);
    
    return {
      repository_id: repositoryId,
      tools: Object.keys(toolResults),
      overlap: {
        common_findings: overlapData.overlap.length,
        unique_findings: overlapData.unique.length,
        total_unique_issues: overlapData.total
      },
      effectiveness: effectiveness,
      by_severity: bySeverity,
      by_category: byCategory,
      detailed_overlap: overlapData.overlap,
      detailed_unique: overlapData.unique
    };
  }

  extractCategory(alert) {
    // Extract category from rule_id or use existing category field
    if (alert.category) return alert.category;
    
    const ruleId = alert.rule_id?.toLowerCase() || '';
    
    if (ruleId.includes('xss')) return 'XSS';
    if (ruleId.includes('sql')) return 'SQL Injection';
    if (ruleId.includes('command')) return 'Command Injection';
    if (ruleId.includes('path')) return 'Path Traversal';
    if (ruleId.includes('csrf')) return 'CSRF';
    if (ruleId.includes('ssrf')) return 'SSRF';
    
    return 'Other';
  }

  /**
   * Print comparison report
   */
  printReport(report) {
    console.log('\n=== Tool Comparison Report ===\n');
    console.log(`Tools Analyzed: ${report.tools.join(', ')}\n`);
    
    console.log('--- Overlap Analysis ---');
    console.log(`Common findings (detected by multiple tools): ${report.overlap.common_findings}`);
    console.log(`Unique findings (detected by one tool): ${report.overlap.unique_findings}`);
    console.log(`Total unique security issues: ${report.overlap.total_unique_issues}\n`);
    
    console.log('--- Tool Effectiveness ---');
    Object.entries(report.effectiveness).forEach(([tool, metrics]) => {
      console.log(`${tool}:`);
      console.log(`  Total detections: ${metrics.total_detections}`);
      console.log(`  Unique detections: ${metrics.unique_detections}`);
      console.log(`  Shared detections: ${metrics.shared_detections}`);
      console.log(`  Uniqueness rate: ${metrics.uniqueness_rate}%`);
    });
    
    console.log('\n--- Findings by Severity ---');
    Object.entries(report.by_severity).forEach(([tool, severities]) => {
      console.log(`${tool}: Critical=${severities.critical}, High=${severities.high}, Medium=${severities.medium}, Low=${severities.low}`);
    });
    
    console.log('\n--- Findings by Category ---');
    Object.entries(report.by_category).forEach(([tool, categories]) => {
      console.log(`${tool}:`);
      Object.entries(categories).forEach(([category, count]) => {
        console.log(`  ${category}: ${count}`);
      });
    });
  }
}

module.exports = ComparisonAnalyzer;

// CLI usage
if (require.main === module) {
  async function main() {
    const storage = new ResultStorage(process.env.MONGODB_URI);
    const analyzer = new ComparisonAnalyzer();
    
    try {
      await storage.connect();
      
      // Get all repositories
      const mongoose = require('mongoose');
      const Repository = mongoose.models.Repository || require('../../database/models/Repository');
      const repos = await Repository.find();
      
      if (repos.length === 0) {
        console.log('No repositories found in database');
        return;
      }
      
      console.log(`Analyzing ${repos.length} repositories...\n`);
      
      for (const repo of repos) {
        const report = await analyzer.compareRepository(repo._id, storage);
        
        if (report.tools.length > 1) {
          console.log(`\n### Repository: ${repo.name} ###`);
          analyzer.printReport(report);
        }
      }
      
    } catch (error) {
      console.error('Analysis failed:', error);
    } finally {
      await storage.disconnect();
    }
  }
  
  main();
}

