#!/usr/bin/env node

/**
 * Performance Benchmark for ReDoS Vulnerabilities
 * Demonstrates the real-world impact of found vulnerabilities
 */

const fs = require('fs');

// Load the vulnerable patterns from our analysis
const analysisResults = JSON.parse(fs.readFileSync('analysis/results/quick-analysis.json', 'utf8'));

function benchmarkPattern(pattern, flags, testInputs, description) {
  console.log(`Testing: ${description}`);
  
  const regex = new RegExp(pattern, flags);
  const results = [];
  
  testInputs.forEach((input, index) => {
    const start = process.hrtime.bigint();
    let timedOut = false;
    
    const timeout = setTimeout(() => {
      timedOut = true;
    }, 5000);
    
    try {
      const result = regex.test(input);
      clearTimeout(timeout);
      
      if (!timedOut) {
        const end = process.hrtime.bigint();
        const duration = Number(end - start) / 1000000;
        console.log(`  Input ${input.length} chars: ${duration.toFixed(3)}ms`);
        
        results.push({
          inputLength: input.length,
          duration,
          result,
          timeout: false
        });
      } else {
        console.log(`  Input ${input.length} chars: TIMEOUT`);
        results.push({
          inputLength: input.length,
          duration: 5000,
          result: 'timeout',
          timeout: true
        });
      }
    } catch (error) {
      clearTimeout(timeout);
      results.push({
        inputLength: input.length,
        duration: 0,
        result: 'error',
        error: error.message
      });
    }
  });
  
  return results;
}

function generateReDoSInputs(pattern) {
  const inputs = [];
  
  // Credit card pattern - test with long sequences that don't match
  if (pattern.includes('5[1-5]') || pattern.includes('222')) {
    inputs.push('5' + '1'.repeat(20) + 'x'); // Invalid ending
    inputs.push('5' + '1'.repeat(50) + 'x');
    inputs.push('5' + '1'.repeat(100) + 'x');
  }
  
  // FQDN pattern - test with nested groups
  if (pattern.includes('a-z') && pattern.includes('{2,}')) {
    inputs.push('a'.repeat(20) + 'x');
    inputs.push('a'.repeat(50) + 'x');
    inputs.push('a'.repeat(100) + 'x');
  }
  
  // HSL pattern - complex nested quantifiers
  if (pattern.includes('hsla?')) {
    inputs.push('hsl(' + '1.'.repeat(20) + 'x');
    inputs.push('hsl(' + '1.'.repeat(50) + 'x');
    inputs.push('hsl(' + '1.'.repeat(100) + 'x');
  }
  
  // Date pattern - complex alternation
  if (pattern.includes('Mon|Tue|Wed')) {
    inputs.push('Mon, ' + '1'.repeat(20) + ' Jan');
    inputs.push('Mon, ' + '1'.repeat(50) + ' Jan');
    inputs.push('Mon, ' + '1'.repeat(100) + ' Jan');
  }
  
  // Format pattern - nested brackets and quantifiers
  if (pattern.includes('\\[') && pattern.includes('MM?M?M?')) {
    inputs.push('[' + 'M'.repeat(20) + 'x');
    inputs.push('[' + 'M'.repeat(50) + 'x');
    inputs.push('[' + 'M'.repeat(100) + 'x');
  }
  
  // Whitespace pattern - exponential backtracking
  if (pattern.includes('\\s\\s*')) {
    inputs.push(' '.repeat(20) + 'x');
    inputs.push(' '.repeat(50) + 'x');
    inputs.push(' '.repeat(100) + 'x');
  }
  
  // Default fallback inputs
  if (inputs.length === 0) {
    inputs.push('a'.repeat(20) + 'x');
    inputs.push('a'.repeat(50) + 'x');
    inputs.push('a'.repeat(100) + 'x');
  }
  
  return inputs;
}

function main() {
  console.log('ReDoS Performance Benchmark');
  
  const allBenchmarks = {};
  
  // Test vulnerable patterns from each project
  Object.keys(analysisResults.results).forEach(project => {
    const vulnerablePatterns = analysisResults.results[project].vulnerable;
    
    if (vulnerablePatterns.length > 0) {
      console.log(`\nAnalyzing ${project}: ${vulnerablePatterns.length} vulnerable patterns`);
      
      allBenchmarks[project] = [];
      
      // Test top 3 most critical patterns
      vulnerablePatterns.slice(0, 3).forEach((vuln, index) => {
        const testInputs = generateReDoSInputs(vuln.pattern);
        const description = `${project} vulnerability ${index + 1}`;
        
        const benchmarkResults = benchmarkPattern(
          vuln.pattern,
          vuln.flags,
          testInputs,
          description
        );
        
        allBenchmarks[project].push({
          pattern: vuln.pattern,
          file: vuln.file,
          results: benchmarkResults
        });
      });
    }
  });
  
  console.log('\nPERFORMANCE SUMMARY:');
  
  Object.keys(allBenchmarks).forEach(project => {
    console.log(`\n${project}:`);
    
    allBenchmarks[project].forEach((benchmark, index) => {
      const maxTime = Math.max(...benchmark.results.filter(r => !r.timeout).map(r => r.duration));
      const hasTimeout = benchmark.results.some(r => r.timeout);
      
      let status = 'LOW';
      if (hasTimeout) status = 'CRITICAL';
      else if (maxTime > 1000) status = 'HIGH';
      else if (maxTime > 100) status = 'MEDIUM';
      
      console.log(`  ${benchmark.file.split('/').pop()}: ${status} (max: ${maxTime.toFixed(0)}ms)`);
    });
  });
  
  // Save benchmark results
  const benchmarkData = {
    timestamp: new Date().toISOString(),
    summary: 'Performance benchmark of vulnerable regex patterns',
    methodology: 'Tested with increasing input sizes to demonstrate exponential growth',
    results: allBenchmarks
  };
  
  fs.writeFileSync('analysis/results/performance-benchmark.json', JSON.stringify(benchmarkData, null, 2));
  console.log('\nBenchmark results saved to: analysis/results/performance-benchmark.json');
}

if (require.main === module) {
  main();
} 