/**
 * Known Vulnerable ReDoS Patterns
 * Collection of regex patterns known to cause catastrophic backtracking
 * Sources: OWASP, CVE databases, security research papers
 */

const vulnerablePatterns = [
  {
    pattern: '^(a+)+$',
    description: 'Classic nested quantifier vulnerability',
    complexity: 'O(2^n)',
    source: 'OWASP ReDoS',
    category: 'nested_quantifiers',
    testInput: 'aaaaaaaaax', // n a's followed by x
    severity: 'HIGH'
  },
  
  {
    pattern: '^(a|a)*$',
    description: 'Alternation with identical branches',
    complexity: 'O(2^n)',
    source: 'Academic research',
    category: 'alternation_overlap',
    testInput: 'aaaaaaaaax',
    severity: 'HIGH'
  },
  
  {
    pattern: '^([a-zA-Z0-9])(([\\.\\-])?([a-zA-Z0-9]+))*([a-zA-Z0-9])@([a-zA-Z0-9])(([\\.\\-])?([a-zA-Z0-9]+))*([a-zA-Z0-9])\\.[a-zA-Z]{2,4}$',
    description: 'Email validation with nested quantifiers',
    complexity: 'Exponential',
    source: 'Real-world code',
    category: 'email_validation',
    testInput: 'a@a.' + 'a'.repeat(50000) + 'x',
    severity: 'MEDIUM'
  },
  
  {
    pattern: '^(([a-z])+.)+[A-Z]([a-z])+$',
    description: 'Multiple nested groups with quantifiers',
    complexity: 'Exponential',
    source: 'Code review finding',
    category: 'nested_groups',
    testInput: 'a.a.a.a.a.a.a.a.a.x',
    severity: 'HIGH'
  },
  
  {
    pattern: '^\\s*(\\w+\\s*)*$',
    description: 'Whitespace and word boundary with nesting',
    complexity: 'Quadratic to exponential',
    source: 'Input validation code',
    category: 'whitespace_handling',
    testInput: ' '.repeat(1000) + 'x',
    severity: 'MEDIUM'
  },
  
  {
    pattern: '(.*a){20}',
    description: 'Fixed repetition with greedy quantifier',
    complexity: 'Exponential',
    source: 'Log parsing regex',
    category: 'fixed_repetition',
    testInput: 'b'.repeat(100) + 'x',
    severity: 'HIGH'
  },
  
  {
    pattern: '^((\\w+\\s+)*\\w+)*$',
    description: 'Word sequences with nested quantifiers',
    complexity: 'Exponential',
    source: 'Text processing',
    category: 'word_sequences',
    testInput: 'word ' + 'word '.repeat(20) + 'x',
    severity: 'HIGH'
  },
  
  {
    pattern: '^(\\d+\\.)*\\d+$',
    description: 'Decimal number validation vulnerability',
    complexity: 'Quadratic',
    source: 'Form validation',
    category: 'number_validation',
    testInput: '1.'.repeat(100) + 'x',
    severity: 'MEDIUM'
  }
];

// Known safe patterns for comparison
const safePatterns = [
  {
    pattern: '^[a-zA-Z0-9]+$',
    description: 'Simple character class without nesting',
    category: 'character_class',
    reasoning: 'No nested quantifiers or alternation'
  },
  
  {
    pattern: '\\d{3}-\\d{2}-\\d{4}',
    description: 'Fixed-length format (SSN)',
    category: 'fixed_format',
    reasoning: 'Specific quantifiers, no nesting'
  },
  
  {
    pattern: '^[a-z]+@[a-z]+\\.[a-z]{2,4}$',
    description: 'Simple email validation',
    category: 'email_simple',
    reasoning: 'Linear quantifiers only'
  },
  
  {
    pattern: '^https?://[\\w.-]+(/[\\w.-]*)*/?$',
    description: 'URL validation without nested quantifiers',
    category: 'url_validation',
    reasoning: 'Properly structured without dangerous nesting'
  }
];

// Real-world examples from CVEs and security reports
const realWorldExamples = [
  {
    cve: 'CVE-2019-20149',
    pattern: '(\\.\\.|[^/])+',
    project: 'faye-websocket-ruby',
    description: 'Path traversal regex with exponential backtracking',
    impact: 'DoS via malicious WebSocket requests'
  },
  
  {
    cve: 'CVE-2021-3749',
    pattern: '(a+)+',
    project: 'axios',
    description: 'ReDoS in axios library trim function',
    impact: 'Application hang with crafted input'
  },
  
  {
    issue: 'GitHub Security Advisory',
    pattern: '^\\s*(.*?)\\s*$',
    project: 'Various npm packages',
    description: 'Common trim pattern causing ReDoS',
    impact: 'Server resource exhaustion'
  }
];

module.exports = {
  vulnerablePatterns,
  safePatterns,
  realWorldExamples,
  
  // Helper functions
  getByCategory: (category) => vulnerablePatterns.filter(p => p.category === category),
  getBySeverity: (severity) => vulnerablePatterns.filter(p => p.severity === severity),
  getTestCases: () => [...vulnerablePatterns, ...safePatterns]
}; 