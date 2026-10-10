/**
 * Risk Scoring and Classification Aggregator
 * Synthesizes URL Parsing, Heuristics, ML Inference, and Threat Intelligence into a calibrated verdict.
 */

import { safeParseURL, MalformedURLError, UnsupportedSchemeError } from './urlParser.js';
import { extractFeatures } from './featureExtractor.js';
import { evaluateHeuristics } from './heuristicEngine.js';
import { MLEngine } from './mlEngine.js';
import { ThreatIntelManager } from './threatIntelligence.js';

/**
 * @typedef {'LOW_RISK' | 'SUSPICIOUS' | 'HIGH_RISK' | 'ERROR'} RiskCategory
 */

/**
 * @typedef {Object} AnalysisVerdict
 * @property {boolean} safe
 * @property {RiskCategory} category
 * @property {number | null} score - Integer 0-100 (null on error)
 * @property {string} summary
 * @property {Array<{ id: string, severity: string, title: string, description: string }>} reasons
 * @property {string} url
 * @property {string} hostname
 * @property {Object} details
 * @property {number} timestamp
 */

export class RiskScorer {
  /**
   * @param {Object} options
   * @param {MLEngine} [options.mlEngine]
   * @param {ThreatIntelManager} [options.threatIntelManager]
   * @param {number} [options.suspiciousThreshold]
   * @param {number} [options.highRiskThreshold]
   */
  constructor(options = {}) {
    this.mlEngine = options.mlEngine || new MLEngine();
    this.threatIntel = options.threatIntelManager || new ThreatIntelManager();
    this.suspiciousThreshold = options.suspiciousThreshold ?? 35;
    this.highRiskThreshold = options.highRiskThreshold ?? 70;
  }

  /**
   * Performs full analysis of a URL.
   * 
   * @param {string} rawUrl
   * @returns {Promise<AnalysisVerdict>}
   */
  async analyze(rawUrl) {
    const timestamp = Date.now();

    // Step 1: Safe URL Parsing
    let parsed;
    try {
      parsed = safeParseURL(rawUrl);
    } catch (err) {
      return {
        safe: false, // Never safe by default on error!
        category: 'ERROR',
        score: null,
        summary: `Analysis Error: ${err.message}`,
        reasons: [{
          id: 'PARSE_ERROR',
          severity: 'CRITICAL',
          title: 'Invalid or Unsupported URL',
          description: err.message
        }],
        url: rawUrl || '',
        hostname: '',
        details: {
          errorType: err.name,
          errorMessage: err.message
        },
        timestamp
      };
    }

    try {
      // Step 2: Feature Extraction
      const featureResult = extractFeatures(parsed);

      // Step 3: Heuristic Evaluation
      const heuristicResult = evaluateHeuristics(featureResult);

      // Step 4: Machine Learning Inference
      const mlResult = this.mlEngine.predict(featureResult.normalized);

      // Step 5: Threat Intelligence Check
      const threatResult = await this.threatIntel.check(parsed.hostname);

      // Step 6: Risk Aggregation
      let aggregatedScore = 0;
      const combinedReasons = [...heuristicResult.reasons];

      if (mlResult.available && mlResult.probability !== null) {
        // Weighted combination: 45% ML, 55% Heuristic (preventing double counting)
        const mlComponent = mlResult.probability * 100;
        aggregatedScore = Math.round((mlComponent * 0.45) + (heuristicResult.score * 0.55));
      } else {
        // Fallback to pure heuristic score if ML is unavailable
        aggregatedScore = heuristicResult.score;
        combinedReasons.push({
          id: 'ML_UNAVAILABLE',
          severity: 'INFO',
          title: 'ML Model Offline',
          description: 'Machine learning inference was not available; verdict computed via heuristic rules alone.'
        });
      }

      // Step 7: Override logic for Critical Signals & Threat Intelligence
      const hasCriticalHeuristic = combinedReasons.some(r => r.severity === 'CRITICAL');
      if (hasCriticalHeuristic && aggregatedScore < 70) {
        aggregatedScore = 70; // Escalate to high risk if severe indicator present
      }

      if (threatResult.verdict === 'KNOWN_MALICIOUS') {
        aggregatedScore = Math.max(aggregatedScore, 95);
        combinedReasons.unshift({
          id: 'THREAT_INTEL_FLAG',
          severity: 'CRITICAL',
          title: 'Threat Intelligence Match',
          description: threatResult.details || 'Identified as known malicious host in threat feeds.'
        });
      } else if (threatResult.verdict === 'SAFE' && aggregatedScore < 50) {
        // Verified known brand, reduce false-positive noise
        aggregatedScore = Math.max(0, aggregatedScore - 15);
      }

      // Ensure score is bounded [0, 100]
      aggregatedScore = Math.max(0, Math.min(100, aggregatedScore));

      // Step 8: Categorization
      let category;
      let safe;
      let summary;

      if (aggregatedScore >= this.highRiskThreshold) {
        category = 'HIGH_RISK';
        safe = false;
        summary = 'High Risk: Critical phishing or malicious indicators detected.';
      } else if (aggregatedScore >= this.suspiciousThreshold) {
        category = 'SUSPICIOUS';
        safe = false;
        summary = 'Suspicious: Website exhibits unusual or potentially deceptive patterns.';
      } else {
        category = 'LOW_RISK';
        safe = true;
        summary = combinedReasons.length > 0 
          ? 'Low Risk: Minor indicators noted, but within acceptable parameters.'
          : 'Low Risk: No prominent suspicious indicators detected (does not guarantee absolute legitimacy).';
      }

      return {
        safe,
        category,
        score: aggregatedScore,
        summary,
        reasons: combinedReasons,
        url: parsed.url,
        hostname: parsed.hostname,
        details: {
          ml: mlResult,
          heuristic: {
            score: heuristicResult.score
          },
          threatIntel: threatResult,
          features: featureResult.raw,
          domain: parsed.domain
        },
        timestamp
      };
    } catch (err) {
      return {
        safe: false,
        category: 'ERROR',
        score: null,
        summary: `Analysis Pipeline Exception: ${err.message}`,
        reasons: [{
          id: 'PIPELINE_ERROR',
          severity: 'CRITICAL',
          title: 'Analysis Pipeline Error',
          description: err.message
        }],
        url: parsed.url,
        hostname: parsed.hostname,
        details: {
          errorType: err.name,
          errorMessage: err.message
        },
        timestamp
      };
    }
  }
}
