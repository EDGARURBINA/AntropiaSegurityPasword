import { PasswordEvaluator } from '../passwordEvaluator.js';

export class PasswordController {

  static async evaluatePassword(req, res) {
    const requestId = `req_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    
    console.log(`[${new Date().toISOString()}] 🔐 PASSWORD EVALUATION REQUEST`);
    console.log(`[REQUEST] ID: ${requestId}`);
    console.log(`[REQUEST] Method: ${req.method}`);
    console.log(`[REQUEST] IP: ${req.ip || 'unknown'}`);
    console.log(`[SECURITY] Zero persistence policy active`);

    try {
      const validation = PasswordController.validateRequest(req);
      if (!validation.isValid) {
        console.log(`[VALIDATION] Request failed: ${validation.errors.join(', ')}`);
        
        return res.status(400).json({
          success: false,
          error: 'INVALID_REQUEST',
          message: 'Petición inválida',
          details: validation.errors,
          requestId,
          timestamp: new Date().toISOString()
        });
      }

      const { password } = req.body;
      
      console.log(`[INPUT] Password length: ${password?.length || 0} characters`);
      console.log(`[INPUT] Type: ${typeof password}`);
      console.log(`[SECURITY] Password content NOT logged (zero persistence)`);

      console.log(`[PROCESSING] Starting secure evaluation...`);
      const evaluation = await PasswordEvaluator.evaluatePasswordSecurely(password);

      // RESPUESTA JSON COMPLETA 
      const response = {
        success: true,
        data: {
          evaluation: evaluation
        },
        metadata: {
          requestId,
          day1_functions: ['calculate_L', 'calculate_N'], 
          day2_functions: ['calculate_entropy', 'check_password_strength'],
          day3_features: ['secure_api', 'zero_persistence', 'robust_validation'],
          similarity_features: ['character_removal_detection', 'leet_speak_detection', 'substring_matching'],
          endpoint: '/api/v1/password/evaluate',
          processingTime: Date.now(),
          version: '1.1.0'
        },
        timestamp: new Date().toISOString()
      };

      // VERIFICACIÓN DE SEGURIDAD MEJORADA: 
      // Permitir que matchedPassword contenga la contraseña cuando es una coincidencia legítima
      const responseJson = JSON.stringify(response);
      const hasPasswordInResponse = responseJson.includes(password);
      
      if (hasPasswordInResponse) {
        // Verificar si es una aparición legítima en matchedPassword
        const isLegitimateMatch = evaluation.similarityAnalysis?.matchedPassword === password && 
                                 evaluation.similarityAnalysis?.exactMatch === true;
        
        if (!isLegitimateMatch) {
          // Si la contraseña aparece pero NO es en matchedPassword por coincidencia exacta, es un problema
          console.error(`[SECURITY] ⚠️ ALERT: Password found in unexpected location in response!`);
          console.error(`[SECURITY] This may indicate a security issue in the evaluation logic`);
          throw new Error('SECURITY_BREACH: Password in response (unexpected location)');
        } else {
          // Es una aparición legítima - la contraseña está en el diccionario
          console.log(`[SECURITY] ✅ Password appears in matchedPassword due to exact dictionary match - this is expected`);
          console.log(`[SECURITY] ⚠️ WARNING: User entered a password that exactly matches a common password`);
        }
      }

      // LOG SEGURO: Solo resultados
      console.log(`[RESULT] Entropy: ${evaluation.entropyAnalysis.value} bits`);
      console.log(`[RESULT] Category: ${evaluation.strengthEvaluation.finalCategory}`);
      console.log(`[RESULT] In dictionary: ${evaluation.dictionaryAnalysis.isCommonPassword ? 'YES' : 'NO'}`);
      
      // LOGS DE SIMILITUD
      console.log(`[SIMILARITY] Is similar: ${evaluation.similarityAnalysis.isSimilar ? 'YES' : 'NO'}`);
      if (evaluation.similarityAnalysis.isSimilar) {
        console.log(`[SIMILARITY] Type: ${evaluation.similarityAnalysis.similarityType}`);
        console.log(`[SIMILARITY] Risk level: ${evaluation.similarityAnalysis.riskLevel}`);
        console.log(`[SIMILARITY] Dataset used: ${evaluation.similarityAnalysis.datasetUsed} passwords`);
        
        // Log especial para coincidencias exactas
        if (evaluation.similarityAnalysis.exactMatch) {
          console.log(`[SIMILARITY] 🚨 EXACT MATCH: User password is identical to a common password in dataset`);
        }
      }
      
      console.log(`[RESULT] Request ID: ${requestId} completed successfully`);
      console.log(`[SECURITY] ✅ Response sanitized and verified\n`);

      res.status(200).json(response);

    } catch (error) {
      console.error(`[ERROR] ==========================================`);
      console.error(`[ERROR] Evaluation failed for request ${requestId}`);
      console.error(`[ERROR] Error type: ${error.constructor.name}`);
      console.error(`[ERROR] Error message: ${error.message}`);
      console.error(`[ERROR] ==========================================`);

      const isDevelopment = process.env.NODE_ENV !== 'production';
      
      const errorResponse = {
        success: false,
        error: PasswordController.sanitizeErrorType(error),
        message: PasswordController.sanitizeErrorMessage(error),
        requestId,
        timestamp: new Date().toISOString(),
        ...(isDevelopment && {
          debug: {
            errorType: error.constructor.name,
            originalMessage: error.message,
            note: 'Debug info only shown in development'
          }
        })
      };

      const statusCode = PasswordController.getErrorStatusCode(error);
      res.status(statusCode).json(errorResponse);
    }
  }

  /**
   * GENERADOR DE CONTRASEÑAS SEGURAS 
   */
  static async generatePassword(req, res) {
    try {
      const { length = 16, includeLowercase = true, includeUppercase = true, includeNumbers = true, includeSymbols = true } = req.body || {};

      if (typeof length !== 'number' || length < 4 || length > 100) {
        return res.status(400).json({
          success: false,
          error: 'INVALID_LENGTH',
          message: 'La longitud debe ser un número entre 4 y 100',
          timestamp: new Date().toISOString()
        });
      }

      const generatedPassword = PasswordEvaluator.generateSecurePassword(length, {
        includeLowercase, includeUppercase, includeNumbers, includeSymbols
      });

      const evaluation = await PasswordEvaluator.evaluatePasswordSecurely(generatedPassword);

      const response = {
        success: true,
        data: {
          generatedPassword,
          evaluation,
          parameters: { length, includeLowercase, includeUppercase, includeNumbers, includeSymbols },
          generator: 'CSPRNG (crypto.getRandomValues)'
        },
        timestamp: new Date().toISOString()
      };

      res.status(200).json(response);

    } catch (error) {
      console.error(`[ERROR] Password generation failed:`, error);
      res.status(500).json({
        success: false,
        error: 'GENERATION_ERROR',
        message: error.message,
        timestamp: new Date().toISOString()
      });
    }
  }

  /**
   * ENDPOINT DE DEBUG
   */
  static async debugInfo(req, res) {
    try {
      console.log(`[DEBUG] Debug endpoint called`);
      
      const debugInfo = {
        passwordEvaluator: {
          exists: typeof PasswordEvaluator !== 'undefined',
          methods: Object.getOwnPropertyNames(PasswordEvaluator).filter(name => typeof PasswordEvaluator[name] === 'function'),
          dictionaryLoaded: PasswordEvaluator.isDictionaryLoaded || false,
          dictionarySize: PasswordEvaluator.commonPasswords?.size || 0
        },
        environment: {
          nodeVersion: process.version,
          nodeEnv: process.env.NODE_ENV || 'development',
          platform: process.platform,
          workingDirectory: process.cwd()
        }
      };

      // Intentar cargar el diccionario para debug
      try {
        await PasswordEvaluator.ensureDictionaryLoaded();
        debugInfo.passwordEvaluator.dictionaryLoaded = PasswordEvaluator.isDictionaryLoaded;
        debugInfo.passwordEvaluator.dictionarySize = PasswordEvaluator.commonPasswords.size;
        
        // Verificar si algunas contraseñas comunes están en el diccionario
        const testPasswords = ['123456', 'password', 'qwerty', 'admin'];
        debugInfo.dictionaryTests = {};
        for (const pwd of testPasswords) {
          debugInfo.dictionaryTests[pwd] = PasswordEvaluator.commonPasswords.has(pwd);
        }
        
      } catch (dictError) {
        debugInfo.dictionaryError = {
          message: dictError.message,
          type: dictError.constructor.name
        };
      }

      res.status(200).json({
        success: true,
        debug: debugInfo,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error(`[DEBUG] Debug endpoint error:`, error);
      res.status(500).json({
        success: false,
        error: 'DEBUG_ERROR',
        message: error.message,
        timestamp: new Date().toISOString()
      });
    }
  }

  /**
   * INFORMACIÓN DE LA API
   */
  static getApiInfo(req, res) {
    const apiInfo = {
      name: 'Password Entropy Evaluation API',
      version: '1.1.0',
      description: 'API completa para evaluar la fuerza de contraseñas con detección avanzada de similitud',
      
      endpoints: {
        evaluate: {
          method: 'POST',
          path: '/api/v1/password/evaluate',
          description: 'Evalúa la fuerza de una contraseña con análisis de similitud',
          note: 'Si la contraseña coincide exactamente con una del diccionario, aparecerá en matchedPassword'
        },
        generate: {
          method: 'POST', 
          path: '/api/v1/password/generate',
          description: 'Genera contraseña segura con CSPRNG'
        },
        info: {
          method: 'GET',
          path: '/api/v1/password/info', 
          description: 'Información de la API'
        },
        debug: {
          method: 'GET',
          path: '/api/v1/password/debug',
          description: 'Información de debug (temporal)'
        }
      },

      security: {
        zeroPersistence: 'Las contraseñas NUNCA se almacenan ni registran',
        smartSanitization: 'Permite matchedPassword para coincidencias legítimas del diccionario',
        secureLogging: 'Solo metadatos, nunca datos sensibles'
      },

      timestamp: new Date().toISOString()
    };

    res.status(200).json(apiInfo);
  }

  /**
   * UTILIDADES DE VALIDACIÓN Y SEGURIDAD
   */
  static validateRequest(req) {
    const errors = [];

    const contentType = req.get('Content-Type');
    if (!contentType || !contentType.includes('application/json')) {
      errors.push('CONTENT_TYPE_INVALID: Se requiere application/json');
    }

    if (!req.body || typeof req.body !== 'object') {
      errors.push('BODY_MISSING: Body de petición requerido');
    }

    if (req.body && !req.body.hasOwnProperty('password')) {
      errors.push('FIELD_MISSING: Campo "password" requerido');
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  static sanitizeErrorType(error) {
    const allowedTypes = ['INVALID_TYPE', 'EMPTY_INPUT', 'TOO_LONG', 'ValidationError'];
    return allowedTypes.includes(error.message.split(':')[0]) ? 
           error.message.split(':')[0] : 'PROCESSING_ERROR';
  }

  static sanitizeErrorMessage(error) {
    const safeMessages = {
      'INVALID_TYPE': 'Tipo de dato incorrecto',
      'EMPTY_INPUT': 'Entrada vacía',
      'TOO_LONG': 'Entrada demasiado larga',
      'ValidationError': 'Error de validación'
    };

    const errorType = error.message.split(':')[0];
    return safeMessages[errorType] || 'Error interno del servidor';
  }

  static getErrorStatusCode(error) {
    const statusCodes = {
      'INVALID_TYPE': 400,
      'EMPTY_INPUT': 400, 
      'TOO_LONG': 400,
      'ValidationError': 400
    };

    const errorType = error.message.split(':')[0];
    return statusCodes[errorType] || 500;
  }

  static notFound(req, res) {
    res.status(404).json({
      success: false,
      error: 'ENDPOINT_NOT_FOUND',
      message: 'Endpoint no encontrado',
      availableEndpoints: [
        'GET /health',
        'GET /api/v1/password/info',
        'GET /api/v1/password/debug',
        'POST /api/v1/password/evaluate', 
        'POST /api/v1/password/generate'
      ],
      timestamp: new Date().toISOString()
    });
  }
}