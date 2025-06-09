#!/usr/bin/env node

/**
 * ReDoS Mitigation Examples
 * Demonstrates how to fix vulnerable regex patterns
 */

const fs = require('fs');

// Load vulnerable patterns from analysis
const analysisResults = JSON.parse(fs.readFileSync('analysis/results/quick-analysis.json', 'utf8'));

// Mitigation strategies
const mitigationStrategies = {
  
  // Strategy 1: Use RE2 engine (linear time complexity)
  useRE2: {
    name: 'Use RE2 Engine',
    description: 'Replace JavaScript regex engine with Google\'s RE2 for linear time complexity',
    example: `
// Before (vulnerable)
const regex = /^(a+)+$/;
const result = regex.test(input);

// After (safe with RE2)
const RE2 = require('re2');
const regex = new RE2('^(a+)+$');
const result = regex.test(input);
`,
    pros: ['Guaranteed linear time', 'Drop-in replacement', 'No pattern changes needed'],
    cons: ['Additional dependency', 'Some JS regex features not supported', 'Performance overhead for simple patterns']
  },

  // Strategy 2: Rewrite patterns to avoid nesting
  rewritePattern: {
    name: 'Rewrite Vulnerable Patterns',
    description: 'Modify regex patterns to eliminate nested quantifiers and dangerous alternation',
    examples: [
      {
        vulnerable: '^(a+)+$',
        safe: '^a+$',
        explanation: 'Remove nested quantifiers - single quantifier achieves same result'
      },
      {
        vulnerable: '^(a|a)*$',
        safe: '^a*$',
        explanation: 'Eliminate redundant alternation branches'
      },
      {
        vulnerable: '(.*a){20}',
        safe: '(?:[^a]*a){20}',
        explanation: 'Use possessive quantifiers or character classes to prevent backtracking'
      }
    ]
  },

  // Strategy 3: Input validation and limits
  inputValidation: {
    name: 'Input Validation and Limits',
    description: 'Validate and limit input size before regex processing',
    example: `
// Before (vulnerable to large inputs)
function validateEmail(email) {
  const regex = /^([a-zA-Z0-9])(([\\.\\-])?([a-zA-Z0-9]+))*([a-zA-Z0-9])@([a-zA-Z0-9])(([\\.\\-])?([a-zA-Z0-9]+))*([a-zA-Z0-9])\\.[a-zA-Z]{2,4}$/;
  return regex.test(email);
}

// After (safe with input limits)
function validateEmail(email) {
  // Limit input size
  if (!email || email.length > 254) {
    return false;
  }
  
  // Use simpler, safer pattern
  const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$/;
  return regex.test(email);
}
`,
    pros: ['Simple to implement', 'Prevents resource exhaustion', 'Works with existing patterns'],
    cons: ['May reject valid inputs', 'Requires careful limit selection', 'Not a complete solution']
  },

  // Strategy 4: Timeout mechanisms
  timeoutMechanism: {
    name: 'Timeout Mechanisms',
    description: 'Implement timeouts to prevent long-running regex operations',
    example: `
// Timeout wrapper for regex operations
function safeRegexTest(pattern, input, timeoutMs = 1000) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('Regex timeout - possible ReDoS'));
    }, timeoutMs);
    
    try {
      const regex = new RegExp(pattern);
      const result = regex.test(input);
      clearTimeout(timeout);
      resolve(result);
    } catch (error) {
      clearTimeout(timeout);
      reject(error);
    }
  });
}

// Usage
try {
  const result = await safeRegexTest('^(a+)+$', 'aaaaaaaaax', 1000);
  console.log('Result:', result);
} catch (error) {
  console.log('Regex operation failed or timed out:', error.message);
}
`,
    pros: ['Prevents hanging', 'Works with any pattern', 'Configurable limits'],
    cons: ['Async complexity', 'May interrupt valid operations', 'Resource still consumed during timeout period']
  }
};

function demonstrateMitigation(vulnerablePattern, project, file) {
  console.log(`\nMitigation for ${project} (${file}):`);
  console.log(`Pattern: ${vulnerablePattern.substring(0, 60)}${vulnerablePattern.length > 60 ? '...' : ''}`);

  // Specific mitigation for credit card pattern
  if (vulnerablePattern.includes('5[1-5]') && vulnerablePattern.includes('222')) {
    console.log('Mitigation: Pattern Rewriting');
    
    console.log('\n// BEFORE (vulnerable):');
    console.log(`const creditCardRegex = /${vulnerablePattern}/;`);
    
    console.log('\n// AFTER (safer approach):');
    console.log(`// Split into separate, simpler patterns
const mastercardRegex = /^5[1-5][0-9]{14}$/;
const visaRegex = /^4[0-9]{12}(?:[0-9]{3})?$/;

function validateCreditCard(number) {
  // Input validation first
  if (!number || number.length < 13 || number.length > 19) {
    return false;
  }
  
  // Remove spaces and dashes
  const cleaned = number.replace(/[\\s-]/g, '');
  
  // Test against individual patterns (linear time)
  return mastercardRegex.test(cleaned) || visaRegex.test(cleaned);
}`);
  }

  // Specific mitigation for FQDN pattern
  else if (vulnerablePattern.includes('a-z') && vulnerablePattern.includes('{2,}')) {
    console.log('Mitigation: Input Validation + Simpler Pattern');
    
    console.log('\n// BEFORE (vulnerable):');
    console.log(`const fqdnRegex = /${vulnerablePattern}/i;`);
    
    console.log('\n// AFTER (safer approach):');
    console.log(`function validateFQDN(domain) {
  // Input validation
  if (!domain || domain.length > 253) {
    return false;
  }
  
  // Split and validate each label separately
  const labels = domain.split('.');
  if (labels.length < 2) {
    return false;
  }
  
  // Validate each label with simple pattern
  const labelRegex = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i;
  return labels.every(label => 
    label.length > 0 && 
    label.length <= 63 && 
    labelRegex.test(label)
  );
}`);
  }

  // Specific mitigation for HSL pattern
  else if (vulnerablePattern.includes('hsla?')) {
    console.log('Mitigation: Structured Parsing');
    
    console.log('\n// BEFORE (vulnerable):');
    console.log(`const hslRegex = /${vulnerablePattern.substring(0, 80)}...}/i;`);
    
    console.log('\n// AFTER (safer approach):');
    console.log(`function validateHSL(hslString) {
  // Input validation
  if (!hslString || hslString.length > 100) {
    return false;
  }
  
  // Use structured parsing instead of complex regex
  const trimmed = hslString.trim();
  const isHsla = trimmed.startsWith('hsla(');
  const isHsl = trimmed.startsWith('hsl(');
  
  if (!isHsl && !isHsla) {
    return false;
  }
  
  // Extract content between parentheses
  const content = trimmed.slice(isHsla ? 5 : 4, -1);
  const parts = content.split(',').map(p => p.trim());
  
  // Validate number of parts
  const expectedParts = isHsla ? 4 : 3;
  if (parts.length !== expectedParts) {
    return false;
  }
  
  // Validate each part with simple patterns
  const numberRegex = /^[+-]?\\d*\\.?\\d+$/;
  return parts.every(part => numberRegex.test(part.replace(/%$/, '')));
}`);
  }

  // Generic RE2 mitigation
  else {
    console.log('Mitigation: Use RE2 Engine');
    
    console.log('\n// BEFORE (vulnerable):');
    console.log(`const regex = /${vulnerablePattern}/;`);
    
    console.log('\n// AFTER (safe with RE2):');
    console.log(`const RE2 = require('re2');
const regex = new RE2('${vulnerablePattern}');

// RE2 guarantees linear time complexity
// No exponential backtracking possible`);
  }


}

function main() {
  console.log('ReDoS Mitigation Examples');
  
  Object.keys(analysisResults.results).forEach(project => {
    const vulnerablePatterns = analysisResults.results[project].vulnerable;
    
    // Show mitigation for the most critical pattern from each project
    if (vulnerablePatterns.length > 0) {
      const mostCritical = vulnerablePatterns[0];
      demonstrateMitigation(
        mostCritical.pattern,
        project,
        mostCritical.file.split('/').pop()
      );
    }
  });

  // Generate mitigation summary
  const mitigationSummary = {
    timestamp: new Date().toISOString(),
    strategies: mitigationStrategies,
    examples: Object.keys(analysisResults.results).map(project => {
      const vulnerablePatterns = analysisResults.results[project].vulnerable;
      return {
        project,
        vulnerableCount: vulnerablePatterns.length,
        mitigationApproach: vulnerablePatterns.length > 0 ? 'Pattern rewriting + input validation' : 'No mitigation needed',
        patterns: vulnerablePatterns.slice(0, 3).map(p => ({
          pattern: p.pattern.substring(0, 100),
          file: p.file.split('/').pop(),
          recommendedFix: 'See mitigation examples'
        }))
      };
    })
  };

  fs.writeFileSync('analysis/results/mitigation-examples.json', JSON.stringify(mitigationSummary, null, 2));
  console.log('\nMitigation examples saved to: analysis/results/mitigation-examples.json');
}

if (require.main === module) {
  main();
} 