#!/usr/bin/env node

/**
 * Quick ReDoS Analysis
 * Focused analysis of the most critical patterns for faster results
 */

const fs = require('fs');
const path = require('path');
const { isSafe } = require('redos-detector');

// Quick regex extraction from specific files
function quickExtract(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const patterns = [];
    
    // Extract literal patterns like /pattern/flags
    const literalMatches = content.match(/\/(?![*\/])([^\/\n\r\\]|\\[^*]|\\.)*\/[gimsuvy]*/g) || [];
    literalMatches.forEach(match => {
      const patternMatch = match.match(/^\/(.*)\/([gimsuvy]*)$/);
      if (patternMatch && patternMatch[1].length > 5) { // Only complex patterns
        patterns.push({
          pattern: patternMatch[1],
          flags: patternMatch[2],
          file: filePath
        });
      }
    });
    
    return patterns;
  } catch (error) {
    return [];
  }
}

function analyzePatterns(patterns, projectName) {
  const vulnerable = [];
  const safe = [];
  
  patterns.forEach((p, index) => {
    try {
      // Skip patterns with problematic flag combinations
      if (p.flags.includes('u') && p.flags.includes('i')) {
        return; // Skip unicode + case insensitive combination
      }
      
      const regexObj = new RegExp(p.pattern, p.flags);
      const analysis = isSafe(regexObj);
      
      if (!analysis.safe) {
        vulnerable.push({
          ...p,
          score: analysis.score,
          infinite: analysis.score.infinite
        });
        console.log(`VULNERABLE: ${p.pattern.substring(0, 60)} (${path.basename(p.file)})`);
      } else {
        safe.push(p);
      }
    } catch (error) {
      // Skip patterns that cause analysis errors
      if (!error.message.includes('Internal error') && !error.message.includes('caseInsensitive')) {
        console.log(`ERROR: ${error.message}`);
      }
    }
  });
  
  return { vulnerable, safe };
}

function main() {
  console.log('Quick ReDoS Analysis');
  
  // Target specific high-value files
  const targetFiles = [
    'analysis/projects/validator.js/src/lib/isCreditCard.js',
    'analysis/projects/validator.js/src/lib/isEmail.js', 
    'analysis/projects/validator.js/src/lib/isFQDN.js',
    'analysis/projects/validator.js/src/lib/isHSL.js',
    'analysis/projects/validator.js/src/lib/isURL.js',
    'analysis/projects/moment/src/lib/create/from-string.js',
    'analysis/projects/moment/src/lib/format/format.js',
    'analysis/projects/chalk/source/index.js'
  ];
  
  const allResults = {};
  
  targetFiles.forEach(file => {
    if (fs.existsSync(file)) {
      const patterns = quickExtract(file);
      if (patterns.length > 0) {
        console.log(`${file}: ${patterns.length} patterns`);
        
        const projectName = file.includes('validator') ? 'validator.js' : 
                          file.includes('moment') ? 'moment.js' : 'chalk';
        
        if (!allResults[projectName]) {
          allResults[projectName] = { vulnerable: [], safe: [] };
        }
        
        const results = analyzePatterns(patterns, projectName);
        allResults[projectName].vulnerable.push(...results.vulnerable);
        allResults[projectName].safe.push(...results.safe);
      }
    }
  });
  
  console.log('\nSUMMARY:');
  
  Object.keys(allResults).forEach(project => {
    const results = allResults[project];
    const total = results.vulnerable.length + results.safe.length;
    
    console.log(`${project}: ${results.vulnerable.length}/${total} vulnerable (${total > 0 ? (results.vulnerable.length / total * 100).toFixed(1) : 0}%)`);
  });
  
  // Save results
  const summaryData = {
    timestamp: new Date().toISOString(),
    analysis: 'quick',
    results: allResults
  };
  
  fs.writeFileSync('analysis/results/quick-analysis.json', JSON.stringify(summaryData, null, 2));
  console.log('Results saved to: analysis/results/quick-analysis.json');
  
  const testCases = [];
  
  Object.keys(allResults).forEach(project => {
    allResults[project].vulnerable.forEach(v => {
      testCases.push({
        project,
        pattern: v.pattern,
        file: v.file,
        testInputs: generateTestInputs(v.pattern)
      });
    });
  });
  
  if (testCases.length > 0) {
    fs.writeFileSync('analysis/results/test-cases.json', JSON.stringify(testCases, null, 2));
    console.log('Test cases saved to: analysis/results/test-cases.json');
  }
}

function generateTestInputs(pattern) {
  // Generate basic test inputs that might trigger ReDoS
  const inputs = [];
  
  // If pattern contains nested quantifiers or alternation
  if (pattern.includes('+') && (pattern.includes('*') || pattern.includes('+'))) {
    inputs.push('a'.repeat(20) + 'x'); // Long string ending with non-matching char
  }
  
  if (pattern.includes('|')) {
    inputs.push('a'.repeat(10) + 'b'.repeat(10) + 'x');
  }
  
  // Email-like patterns
  if (pattern.includes('@') || pattern.includes('\\.')){
    inputs.push('a'.repeat(50) + '@' + 'b'.repeat(50) + '.com');
  }
  
  // URL-like patterns
  if (pattern.includes('http') || pattern.includes('://')){
    inputs.push('http://' + 'a'.repeat(100) + '.com');
  }
  
  // Default long input
  inputs.push('a'.repeat(100) + 'x');
  
  return inputs;
}

if (require.main === module) {
  main();
} 