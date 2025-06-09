#!/usr/bin/env node

/**
 * ReDoS Detection Tools Evaluation
 * Compares different tools on known vulnerable and safe regex patterns
 */

const safeRegex = require('safe-regex');
const { isSafe } = require('redos-detector');

// Test cases - mix of vulnerable and safe patterns
const testCases = [
  // Vulnerable patterns (should be flagged)
  {
    pattern: '^(a+)+$',
    description: 'Classic nested quantifier - vulnerable',
    expected: 'VULNERABLE',
    source: 'OWASP ReDoS examples'
  },
  {
    pattern: '^(a|a)*$',
    description: 'Alternation with overlap - vulnerable', 
    expected: 'VULNERABLE',
    source: 'Known ReDoS pattern'
  },
  {
    pattern: '(a+)+b',
    description: 'Nested quantifiers - vulnerable',
    expected: 'VULNERABLE',
    source: 'Classic ReDoS example'
  },
  {
    pattern: '^([a-zA-Z0-9])(([\\.\\-])?([a-zA-Z0-9]+))*([a-zA-Z0-9])@([a-zA-Z0-9])(([\\.\\-])?([a-zA-Z0-9]+))*([a-zA-Z0-9])\\.[a-zA-Z]{2,4}$',
    description: 'Complex email validation - potentially vulnerable',
    expected: 'VULNERABLE',
    source: 'Real-world email regex'
  },
  
  // Safe patterns (should not be flagged)
  {
    pattern: '^[a-zA-Z0-9]+$',
    description: 'Simple character class - safe',
    expected: 'SAFE',
    source: 'Basic validation'
  },
  {
    pattern: '\\d{3}-\\d{2}-\\d{4}',
    description: 'Fixed length pattern - safe',
    expected: 'SAFE',
    source: 'SSN format'
  },
  {
    pattern: '^[a-z]+@[a-z]+\\.[a-z]{2,4}$',
    description: 'Simple email - safe',
    expected: 'SAFE',
    source: 'Basic email validation'
  }
];

console.log('ReDoS Detection Tools Evaluation');

function evaluateTools() {
  console.log('Testing patterns with different tools...');
  
  const results = {
    'safe-regex': { correct: 0, total: 0, details: [] },
    'redos-detector': { correct: 0, total: 0, details: [] }
  };

  testCases.forEach((testCase, index) => {
    console.log(`Test ${index + 1}: ${testCase.description}`);

    // Test with safe-regex
    try {
      const safeResult = safeRegex(testCase.pattern);
      const safeStatus = safeResult ? 'SAFE' : 'VULNERABLE';
      const safeCorrect = safeStatus === testCase.expected;
      
      console.log(`safe-regex: ${safeStatus} ${safeCorrect ? 'PASS' : 'FAIL'}`);
      
      results['safe-regex'].total++;
      if (safeCorrect) results['safe-regex'].correct++;
      results['safe-regex'].details.push({
        pattern: testCase.pattern,
        expected: testCase.expected,
        actual: safeStatus,
        correct: safeCorrect
      });
    } catch (error) {
      console.log(`safe-regex:     ERROR - ${error.message}`);
      results['safe-regex'].total++;
      results['safe-regex'].details.push({
        pattern: testCase.pattern,
        expected: testCase.expected,
        actual: 'ERROR',
        correct: false
      });
    }

    // Test with redos-detector
    try {
      // Try to create a RegExp from the pattern string
      let regexPattern;
      try {
        regexPattern = new RegExp(testCase.pattern);
      } catch (e) {
        // If pattern is not valid regex, treat as string
        regexPattern = testCase.pattern;
      }
      
      const redosResult = isSafe(regexPattern);
      const redosStatus = redosResult.safe ? 'SAFE' : 'VULNERABLE';
      const redosCorrect = redosStatus === testCase.expected;
      
      console.log(`redos-detector: ${redosStatus} ${redosCorrect ? 'PASS' : 'FAIL'}`);
      
      results['redos-detector'].total++;
      if (redosCorrect) results['redos-detector'].correct++;
      results['redos-detector'].details.push({
        pattern: testCase.pattern,
        expected: testCase.expected,
        actual: redosStatus,
        correct: redosCorrect,
        score: redosResult.score
      });
    } catch (error) {
      console.log(`redos-detector: ERROR - ${error.message}`);
      results['redos-detector'].total++;
      results['redos-detector'].details.push({
        pattern: testCase.pattern,
        expected: testCase.expected,
        actual: 'ERROR',
        correct: false
      });
    }
  });

  console.log('\nEVALUATION SUMMARY:');
  
  Object.keys(results).forEach(tool => {
    const accuracy = results[tool].total > 0 ? 
      (results[tool].correct / results[tool].total * 100).toFixed(1) : 0;
    console.log(`${tool.padEnd(15)}: ${results[tool].correct}/${results[tool].total} correct (${accuracy}%)`);
  });

  // Recommendation
  const bestTool = Object.keys(results).reduce((best, current) => {
    const bestAccuracy = results[best].total > 0 ? results[best].correct / results[best].total : 0;
    const currentAccuracy = results[current].total > 0 ? results[current].correct / results[current].total : 0;
    return currentAccuracy > bestAccuracy ? current : best;
  });
  
  console.log(`\nRecommended tool: ${bestTool}`);

  return results;
}

function performanceTest() {
  console.log('\nPerformance test with vulnerable pattern ^(a+)+$');
  
  const vulnerablePattern = /^(a+)+$/;
  const testInputs = ['aaaaaaaaab', 'aaaaaaaaaaaaaaaab', 'aaaaaaaaaaaaaaaaaaaab'];

  testInputs.forEach(input => {
    const start = process.hrtime.bigint();
    const match = vulnerablePattern.test(input);
    const end = process.hrtime.bigint();
    const duration = Number(end - start) / 1000000;
    
    console.log(`Input length ${input.length}: ${duration.toFixed(3)}ms`);
  });
}

if (require.main === module) {
  evaluateTools();
  performanceTest();
}

module.exports = { evaluateTools, performanceTest }; 