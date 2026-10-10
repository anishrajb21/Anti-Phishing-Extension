/**
 * Machine Learning Inference Engine
 * Executes logistic regression prediction using verified model parameters.
 */

export class MLEngine {
  /**
   * @param {Object} [modelConfig] - Serialized model JSON object
   */
  constructor(modelConfig = null) {
    this.model = null;
    this.isLoaded = false;
    if (modelConfig) {
      this.loadModel(modelConfig);
    }
  }

  /**
   * Loads and validates the model configuration.
   * @param {Object} config
   */
  loadModel(config) {
    if (!config || typeof config !== 'object') {
      throw new Error('Invalid model configuration: must be an object.');
    }

    if (!Array.isArray(config.weights) || typeof config.bias !== 'number') {
      throw new Error('Invalid model schema: missing weights array or bias number.');
    }

    this.model = {
      modelType: config.modelType || 'logistic_regression',
      version: config.version || 'unknown',
      weights: config.weights,
      bias: config.bias,
      threshold: typeof config.threshold === 'number' ? config.threshold : 0.5,
      features: Array.isArray(config.features) ? config.features : []
    };
    this.isLoaded = true;
  }

  /**
   * Sigmoid activation function.
   * @param {number} z
   * @returns {number}
   */
  static sigmoid(z) {
    // Numerically stable sigmoid
    if (z >= 40) return 1.0;
    if (z <= -40) return 0.0;
    return 1 / (1 + Math.exp(-z));
  }

  /**
   * Predicts phishing probability from a normalized feature vector.
   * 
   * @param {number[]} normalizedFeatures
   * @param {number} [customThreshold]
   * @returns {{
   *   available: boolean,
   *   probability: number | null,
   *   isPhishing: boolean | null,
   *   threshold: number,
   *   linearLogOdds: number | null,
   *   modelVersion: string | null,
   *   status: 'SUCCESS' | 'MODEL_UNAVAILABLE' | 'FEATURE_MISMATCH'
   * }}
   */
  predict(normalizedFeatures, customThreshold = null) {
    if (!this.isLoaded || !this.model) {
      return {
        available: false,
        probability: null,
        isPhishing: null,
        threshold: 0.5,
        linearLogOdds: null,
        modelVersion: null,
        status: 'MODEL_UNAVAILABLE'
      };
    }

    if (!Array.isArray(normalizedFeatures) || normalizedFeatures.length !== this.model.weights.length) {
      return {
        available: false,
        probability: null,
        isPhishing: null,
        threshold: this.model.threshold,
        linearLogOdds: null,
        modelVersion: this.model.version,
        status: 'FEATURE_MISMATCH'
      };
    }

    // Dot product: w · x + bias
    let z = this.model.bias;
    for (let i = 0; i < normalizedFeatures.length; i++) {
      z += normalizedFeatures[i] * this.model.weights[i];
    }

    const probability = MLEngine.sigmoid(z);
    const threshold = customThreshold !== null ? customThreshold : this.model.threshold;
    const isPhishing = probability >= threshold;

    return {
      available: true,
      probability: Math.round(probability * 1000) / 1000,
      isPhishing,
      threshold,
      linearLogOdds: Math.round(z * 1000) / 1000,
      modelVersion: this.model.version,
      status: 'SUCCESS'
    };
  }
}
