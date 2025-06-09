#!/usr/bin/env node

/**
 * Regex Pattern Extractor
 * Extracts regular expression patterns from JavaScript files
 */

const fs = require('fs');
const path = require('path');
const { isSafe } = require('redos-detector');

// Patterns to match different regex syntaxes in JavaScript
const regexPatterns = [
  // Literal regex patterns: /pattern/flags
  /\/(?![*\/])([^\/\n\r\\]|\\[^*]|\\.)*\/[gimsuvy]*/g,
  // RegExp constructor: new RegExp('pattern', 'flags')
  /new\s+RegExp\s*\(\s*['"]((?:[^'"\\\n\r]|\\.)*)['"](?:\s*,\s*['"][gimsuvy]*['"])?\s*\)/g,
  // RegExp constructor with variables (basic detection)
  /new\s+RegExp\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*(?:\s*,\s*['"][gimsuvy]*['"])?\s*\)/g
];

function extractRegexFromFile(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const patterns = [];
    
    // Extract literal patterns like /pattern/flags
    const literalMatches = content.match(regexPatterns[0]) || [];
    literalMatches.forEach(match => {
      try {
        // Remove the surrounding slashes and flags to get the pattern
        const patternMatch = match.match(/^\/(.*)\/([gimsuvy]*)$/);
        if (patternMatch) {
          const pattern = patternMatch[1];
          const flags = patternMatch[2];
          patterns.push({
            type: 'literal',
            pattern: pattern,
            flags: flags,
            full: match,
            file: filePath
          });
        }
      } catch (e) {
        // Skip invalid patterns
      }
    });
    
    // Extract RegExp constructor patterns
    const constructorMatches = content.match(regexPatterns[1]) || [];
    constructorMatches.forEach(match => {
      try {
        const patternMatch = match.match(/new\s+RegExp\s*\(\s*['"]([^'"]*)['"]/);
        if (patternMatch) {
          const pattern = patternMatch[1];
          patterns.push({
            type: 'constructor',
            pattern: pattern,
            flags: '',
            full: match,
            file: filePath
          });
        }
      } catch (e) {
        // Skip invalid patterns
      }
    });
    
    return patterns;
  } catch (error) {
    console.error(`Error reading file ${filePath}: ${error.message}`);
    return [];
  }
}

function findJavaScriptFiles(dir, extensions = ['.js', '.ts', '.jsx', '.tsx']) {
  const files = [];
  
  function walkDir(currentDir) {
    const items = fs.readdirSync(currentDir);
    
    for (const item of items) {
      const fullPath = path.join(currentDir, item);
      const stat = fs.statSync(fullPath);
      
      if (stat.isDirectory()) {
        // Skip common directories that likely don't contain source code
        if (!['node_modules', '.git', 'coverage', 'dist', 'build', 'test', 'tests', '__tests__'].includes(item)) {
          walkDir(fullPath);
        }
      } else if (stat.isFile()) {
        const ext = path.extname(item);
        if (extensions.includes(ext)) {
          files.push(fullPath);
        }
      }
    }
  }
  
  walkDir(dir);
  return files;
}

function analyzeProject(projectPath, projectName) {
  console.log(`\n${'='.repeat(50)}`);
  console.log(`Analyzing: ${projectName}`);
  console.log(`${'='.repeat(50)}`);
  
  const jsFiles = findJavaScriptFiles(projectPath);
  console.log(`Found ${jsFiles.length} JavaScript files`);
  
  const allPatterns = [];
  let totalPatterns = 0;
  
  for (const file of jsFiles) {
    const patterns = extractRegexFromFile(file);
    if (patterns.length > 0) {
      console.log(`  ${path.relative(projectPath, file)}: ${patterns.length} patterns`);
      allPatterns.push(...patterns);
      totalPatterns += patterns.length;
    }
  }
  
  console.log(`\nTotal regex patterns found: ${totalPatterns}`);
  
  // Analyze patterns with redos-detector
  console.log('\nAnalyzing patterns for ReDoS vulnerabilities...');
  const vulnerablePatterns = [];
  const safePatterns = [];
  const errorPatterns = [];
  
  for (const patternInfo of allPatterns) {
    try {
      const regexObj = new RegExp(patternInfo.pattern, patternInfo.flags);
      const analysis = isSafe(regexObj);
      
      patternInfo.analysis = analysis;
      
      if (analysis.safe) {
        safePatterns.push(patternInfo);
      } else {
        vulnerablePatterns.push(patternInfo);
        console.log(`  ⚠️  VULNERABLE: ${patternInfo.pattern}`);
        console.log(`      File: ${path.relative(projectPath, patternInfo.file)}`);
        console.log(`      Score: ${analysis.score.value}${analysis.score.infinite ? ' (infinite)' : ''}`);
      }
    } catch (error) {
      errorPatterns.push({ ...patternInfo, error: error.message });
    }
  }
  
  console.log(`\nResults:`);
  console.log(`  Safe patterns: ${safePatterns.length}`);
  console.log(`  Vulnerable patterns: ${vulnerablePatterns.length}`);
  console.log(`  Error patterns: ${errorPatterns.length}`);
  
  // Save results
  const results = {
    project: projectName,
    timestamp: new Date().toISOString(),
    summary: {
      totalFiles: jsFiles.length,
      totalPatterns: totalPatterns,
      safePatterns: safePatterns.length,
      vulnerablePatterns: vulnerablePatterns.length,
      errorPatterns: errorPatterns.length
    },
    vulnerablePatterns,
    safePatterns: safePatterns.slice(0, 10), // Limit safe patterns to keep file size reasonable
    errorPatterns
  };
  
  const resultsFile = `analysis/results/${projectName}-analysis.json`;
  fs.writeFileSync(resultsFile, JSON.stringify(results, null, 2));
  console.log(`\nResults saved to: ${resultsFile}`);
  
  return results;
}

function main() {
  console.log('ReDoS Pattern Extraction and Analysis');
  console.log('=====================================');
  
  const projects = [
    { path: 'analysis/projects/validator.js', name: 'validator.js' },
    { path: 'analysis/projects/moment', name: 'moment.js' },
    { path: 'analysis/projects/chalk', name: 'chalk' }
  ];
  
  const allResults = [];
  
  for (const project of projects) {
    if (fs.existsSync(project.path)) {
      const results = analyzeProject(project.path, project.name);
      allResults.push(results);
    } else {
      console.log(`\nSkipping ${project.name} - directory not found: ${project.path}`);
    }
  }
  
  // Generate summary report
  console.log('\n' + '='.repeat(60));
  console.log('OVERALL SUMMARY');
  console.log('='.repeat(60));
  
  let totalPatterns = 0;
  let totalVulnerable = 0;
  let totalSafe = 0;
  
  allResults.forEach(result => {
    console.log(`\n${result.project}:`);
    console.log(`  Total patterns: ${result.summary.totalPatterns}`);
    console.log(`  Vulnerable: ${result.summary.vulnerablePatterns} (${(result.summary.vulnerablePatterns / result.summary.totalPatterns * 100).toFixed(1)}%)`);
    console.log(`  Safe: ${result.summary.safePatterns} (${(result.summary.safePatterns / result.summary.totalPatterns * 100).toFixed(1)}%)`);
    
    totalPatterns += result.summary.totalPatterns;
    totalVulnerable += result.summary.vulnerablePatterns;
    totalSafe += result.summary.safePatterns;
  });
  
  console.log(`\nCombined totals:`);
  console.log(`  Total patterns analyzed: ${totalPatterns}`);
  console.log(`  Total vulnerable: ${totalVulnerable} (${(totalVulnerable / totalPatterns * 100).toFixed(1)}%)`);
  console.log(`  Total safe: ${totalSafe} (${(totalSafe / totalPatterns * 100).toFixed(1)}%)`);
  
  // Save combined summary
  const summary = {
    timestamp: new Date().toISOString(),
    projects: allResults.map(r => r.summary),
    totals: {
      totalPatterns,
      totalVulnerable,
      totalSafe,
      vulnerabilityRate: (totalVulnerable / totalPatterns * 100).toFixed(1)
    }
  };
  
  fs.writeFileSync('analysis/results/summary.json', JSON.stringify(summary, null, 2));
  console.log(`\nSummary saved to: analysis/results/summary.json`);
  
  console.log('\nNext steps:');
  console.log('1. Review the vulnerable patterns in the results files');
  console.log('2. Investigate specific vulnerabilities for exploitation');
  console.log('3. Create mitigation examples for the most critical issues');
  console.log('4. Document methodology and findings for the report');
}

if (require.main === module) {
  main();
}

module.exports = { extractRegexFromFile, analyzeProject, findJavaScriptFiles }; 