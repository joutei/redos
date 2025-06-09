#!/usr/bin/env node

/**
 * Project Selection Helper
 * Helps identify good target projects for ReDoS analysis
 */

// Suggested target projects with analysis rationale
const targetProjects = [
  {
    name: 'validator.js',
    github: 'https://github.com/validatorjs/validator.js',
    description: 'String validation library',
    rationale: 'Heavy regex usage for email, URL, and format validation',
    priority: 'HIGH',
    expectedRegexCount: '50+',
    knownIssues: 'Multiple ReDoS vulnerabilities reported',
    category: 'validation'
  },
  
  {
    name: 'moment.js',
    github: 'https://github.com/moment/moment',
    description: 'Date manipulation library',
    rationale: 'Complex date parsing with regex patterns',
    priority: 'HIGH', 
    expectedRegexCount: '20+',
    knownIssues: 'Some parsing vulnerabilities documented',
    category: 'parsing'
  },
  
  {
    name: 'chalk',
    github: 'https://github.com/chalk/chalk',
    description: 'Terminal styling',
    rationale: 'Known ReDoS issue (CVE-2021-23454)',
    priority: 'HIGH',
    expectedRegexCount: '5-10',
    knownIssues: 'CVE-2021-23454 - ReDoS in ANSI code parsing',
    category: 'formatting'
  },
  
  {
    name: 'express.js',
    github: 'https://github.com/expressjs/express',
    description: 'Web framework',
    rationale: 'Route parsing and parameter handling',
    priority: 'MEDIUM',
    expectedRegexCount: '15+', 
    knownIssues: 'Various route parsing edge cases',
    category: 'framework'
  },
  
  {
    name: 'lodash',
    github: 'https://github.com/lodash/lodash',
    description: 'Utility library',
    rationale: 'String manipulation and template functions',
    priority: 'MEDIUM',
    expectedRegexCount: '10+',
    knownIssues: 'Template parsing vulnerabilities',
    category: 'utility'
  },
  
  {
    name: 'marked',
    github: 'https://github.com/markedjs/marked',
    description: 'Markdown parser',
    rationale: 'Complex text parsing with nested patterns',
    priority: 'HIGH',
    expectedRegexCount: '30+',
    knownIssues: 'Multiple parsing ReDoS issues',
    category: 'parsing'
  },
  
  {
    name: 'minimatch',
    github: 'https://github.com/isaacs/minimatch',
    description: 'Glob matching utility',
    rationale: 'Pattern matching with potential for catastrophic backtracking',
    priority: 'MEDIUM',
    expectedRegexCount: '10+',
    knownIssues: 'Glob pattern edge cases',
    category: 'matching'
  }
];

// Selection criteria for academic project
const selectionCriteria = {
  primary: [
    'Contains significant regex usage (10+ patterns)',
    'Widely used (high npm download counts)',
    'Active maintenance and real-world deployment',
    'Mix of vulnerable and safe patterns expected'
  ],
  
  secondary: [
    'Known ReDoS issues (for validation)',
    'Different regex categories (validation, parsing, matching)',
    'Varying complexity levels',
    'Good documentation for pattern context'
  ],
  
  practical: [
    'Reasonable codebase size for analysis',  
    'JavaScript/Node.js (aligned with project scope)',
    'Open source with accessible code',
    'Not too many dependencies (easier analysis)'
  ]
};

// Methodology documentation
const methodology = {
  approach: 'Purposive sampling with security focus',
  justification: [
    'Selected projects represent different regex use cases',
    'Mix of known vulnerable and potentially safe projects',
    'High-impact libraries with real-world usage',
    'Manageable scope for academic project timeline'
  ],
  
  categories: {
    validation: 'Libraries focused on input validation',
    parsing: 'Text/data parsing utilities', 
    formatting: 'Output formatting and styling',
    framework: 'Core web framework components',
    utility: 'General purpose utility functions',
    matching: 'Pattern matching and filtering'
  }
};

function printProjectSelection() {
  console.log('='.repeat(60));
  console.log('ReDoS Project - Target Selection Analysis');
  console.log('='.repeat(60));
  
  console.log('\nSELECTION METHODOLOGY:');
  console.log(`Approach: ${methodology.approach}`);
  console.log('\nJustification:');
  methodology.justification.forEach(point => console.log(`  • ${point}`));
  
  console.log('\nPRIMARY SELECTION CRITERIA:');
  selectionCriteria.primary.forEach(criteria => console.log(`  ✓ ${criteria}`));
  
  console.log('\nRECOMMENDED TARGET PROJECTS:');
  console.log('-'.repeat(60));
  
  // Sort by priority
  const sortedProjects = targetProjects.sort((a, b) => {
    const priorityOrder = { 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
    return priorityOrder[b.priority] - priorityOrder[a.priority];
  });
  
  sortedProjects.forEach((project, index) => {
    console.log(`\n${index + 1}. ${project.name} [${project.priority} PRIORITY]`);
    console.log(`   URL: ${project.github}`);
    console.log(`   Category: ${project.category}`);
    console.log(`   Rationale: ${project.rationale}`);
    console.log(`   Expected Patterns: ${project.expectedRegexCount}`);
    if (project.knownIssues) {
      console.log(`   Known Issues: ${project.knownIssues}`);
    }
  });
  
  console.log('\n' + '='.repeat(60));
  console.log('RECOMMENDED FINAL SELECTION (3-5 projects):');
  console.log('='.repeat(60));
  
  const recommended = sortedProjects.filter(p => p.priority === 'HIGH').slice(0, 3);
  const additional = sortedProjects.filter(p => p.priority === 'MEDIUM').slice(0, 2);
  
  console.log('\nCore Projects (Must Include):');
  recommended.forEach((project, index) => {
    console.log(`  ${index + 1}. ${project.name} - ${project.rationale}`);
  });
  
  console.log('\nAdditional Projects (Choose 1-2):');
  additional.forEach((project, index) => {
    console.log(`  ${index + 1}. ${project.name} - ${project.rationale}`);
  });
  
  console.log('\nThis selection provides:');
  console.log('  • Mix of known vulnerable and potentially safe projects');
  console.log('  • Different regex usage patterns and complexity levels');
  console.log('  • Real-world, widely-used libraries');
  console.log('  • Manageable scope for 5-week project timeline');
  
  console.log('\nNEXT STEPS:');
  console.log('1. Clone recommended repositories');
  console.log('2. Perform initial regex pattern extraction');
  console.log('3. Apply detection tool to extracted patterns');
  console.log('4. Validate findings against known issues');
}

function generateProjectCommands() {
  console.log('\n' + '='.repeat(60));
  console.log('QUICK START COMMANDS');
  console.log('='.repeat(60));
  
  const topProjects = targetProjects.filter(p => p.priority === 'HIGH').slice(0, 3);
  
  console.log('\nClone target projects:');
  topProjects.forEach(project => {
    const repoName = project.github.split('/').pop();
    console.log(`git clone ${project.github} analysis/projects/${repoName}`);
  });
  
  console.log('\nCreate analysis directory structure:');
  console.log('mkdir -p analysis/projects analysis/results analysis/patterns');
  
  console.log('\nNext: Run regex extraction on cloned projects');
}

// Export for use in other scripts
module.exports = {
  targetProjects,
  selectionCriteria,
  methodology,
  getHighPriorityProjects: () => targetProjects.filter(p => p.priority === 'HIGH'),
  getByCategory: (category) => targetProjects.filter(p => p.category === category)
};

// Run if called directly
if (require.main === module) {
  printProjectSelection();
  generateProjectCommands();
} 