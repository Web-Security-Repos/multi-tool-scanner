const { connectToDatabase } = require('../../database/config/connection');
const mongoose = require('mongoose');

/**
 * Store normalized scan results in MongoDB
 * Extends the existing Analysis and Alert models to support multiple tools
 */

class ResultStorage {
  constructor(mongoUri) {
    this.mongoUri = mongoUri;
    this.connected = false;
  }

  async connect() {
    try {
      await connectToDatabase();  // Use shared connection module
      this.connected = true;
      console.log('✅ Using shared MongoDB connection');
    } catch (error) {
      console.error('❌ MongoDB connection failed:', error.message);
      throw error;
    }
  }

  async disconnect() {
    // Don't disconnect - let the app manage it
    this.connected = false;
    console.log('Storage released (connection managed by app)');
  }

  /**
   * Get or create repository record
   */
  async getOrCreateRepository(repoName, repoPath) {
    const Repository = require('../../database/models/Repository');
    
    let repo = await Repository.findOne({ name: repoName });
    
    if (!repo) {
      repo = await Repository.create({
        name: repoName,
        full_name: `local/${repoName}`,
        owner: 'local',
        url: repoPath,
        html_url: repoPath,
        language: 'JavaScript',
        codeql_enabled: false
      });
      console.log(`Created repository: ${repoName}`);
    }
    
    return repo;
  }

  /**
   * Store analysis and alerts
   */
  async storeAnalysis(normalizedResult) {
    const Analysis = require('../../database/models/Analysis');
    const Alert = require('../../database/models/Alert');
    
    try {
      // Get or create repository
      const repository = await this.getOrCreateRepository(
        normalizedResult.repository,
        normalizedResult.repository_path || normalizedResult.repository
      );

      // Create analysis record
      const analysis = await Analysis.create({
        analysis_id: `${normalizedResult.tool_name.toLowerCase()}-${Date.now()}-${repository._id}`,
        repository: repository._id,
        commit_sha: 'local-scan',
        ref: 'main',
        tool_name: normalizedResult.tool_name,
        tool_version: normalizedResult.tool_version,
        results_count: normalizedResult.results_count,
        created_at: new Date(normalizedResult.scan_date),
        sarif_stored: false
      });

      console.log(`Created analysis: ${analysis.analysis_id}`);

      // Store alerts
      let alertCount = 0;
      for (const alert of normalizedResult.alerts) {
        await Alert.create({
          alert_number: ++alertCount,
          analysis: analysis._id,
          repository: repository._id,
          rule_id: alert.rule_id,
          rule_description: alert.rule_description,
          severity: alert.severity,
          security_severity: alert.security_severity,
          state: alert.state,
          location: alert.location,
          message: alert.message,
          created_at: new Date(normalizedResult.scan_date),
          updated_at: new Date(normalizedResult.scan_date)
        });
      }

      console.log(`Stored ${alertCount} alerts for ${normalizedResult.repository}`);

      // Update repository last scan time
      repository.last_scan_at = new Date();
      await repository.save();

      return { analysis, alertCount };

    } catch (error) {
      console.error(`Error storing analysis for ${normalizedResult.repository}:`, error.message);
      throw error;
    }
  }

  /**
   * Store multiple analyses
   */
  async storeMultiple(normalizedResults) {
    const results = [];
    
    for (const result of normalizedResults) {
      try {
        const stored = await this.storeAnalysis(result);
        results.push({ success: true, ...stored });
      } catch (error) {
        console.error(`Storage error for ${result.repository}:`, error.message);
        results.push({ 
          success: false, 
          repository: result.repository, 
          error: error.message 
        });
      }
    }
    
    return results;
  }

  /**
   * Get analyses by tool
   */
  async getAnalysesByTool(toolName, limit = 10) {
    const Analysis = require('../../database/models/Analysis');
    
    return await Analysis.find({ tool_name: toolName })
      .populate('repository')
      .sort({ created_at: -1 })
      .limit(limit);
  }

  /**
   * Get comparison data for a repository
   */
  async getToolComparison(repositoryId) {
    const Alert = require('../../database/models/Alert');
    
    const alerts = await Alert.find({ repository: repositoryId })
      .populate('analysis');
    
    const byTool = {};
    
    alerts.forEach(alert => {
      const toolName = alert.analysis.tool_name;
      if (!byTool[toolName]) {
        byTool[toolName] = [];
      }
      byTool[toolName].push(alert);
    });
    
    return byTool;
  }
}

module.exports = ResultStorage;

