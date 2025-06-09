# ReDoS Detection and Mitigation Project

## Overview
Complete ReDoS (Regular Expression Denial of Service) detection and mitigation system for JavaScript applications. This academic project demonstrates vulnerability discovery, analysis, and mitigation strategies using real-world open-source libraries.

## 🎯 Project Status: COMPLETED ✅

**Key Results:**
- **9 ReDoS vulnerabilities** discovered across 3 popular JavaScript libraries
- **100% accurate** detection tool selected and implemented
- **Performance benchmarking** completed for all vulnerabilities
- **Mitigation strategies** demonstrated with practical examples

## 📁 Project Structure
```
Project/
├── src/                          # Analysis pipeline source code
│   ├── tool-evaluation/          # ReDoS detection tool comparison
│   ├── quick-analysis.js         # Main vulnerability discovery script
│   ├── performance-benchmark.js  # Performance impact testing
│   ├── mitigation-examples.js    # Mitigation strategy generator
│   ├── regex-extractor.js        # Regex pattern extraction from codebases
│   └── project-selection.js      # Target project selection methodology
├── analysis/                     # Analysis data and results
│   ├── results/                  # JSON results from pipeline execution
│   ├── projects/                 # Target project codebases (validator.js, moment.js, chalk)
│   └── patterns/                 # Extracted regex patterns by project
├── tests/                        # Test cases and known vulnerable patterns
└── report.pdf                    # Project report
```

## 🚀 Quick Start

### Run Complete Analysis Pipeline
```bash
# Option 1: Run entire pipeline at once
npm run pipeline

# Option 2: Run individual components
npm run evaluate-tools    # Tool comparison
npm run analyze           # Vulnerability discovery  
npm run benchmark         # Performance testing
npm run mitigation        # Generate mitigation examples
```

### View Results
```bash
# Analysis summary
cat analysis/results/quick-analysis.json

# Performance data
cat analysis/results/performance-benchmark.json

# Mitigation examples
cat analysis/results/mitigation-examples.json
```

## 🔍 Key Findings

### Vulnerabilities Discovered
- **validator.js**: 4/25 patterns vulnerable (16.0%)
  - Credit card validation (Mastercard pattern)
  - FQDN validation (Unicode domain handling)
  - HSL color parsing (nested quantifiers)

- **moment.js**: 5/33 patterns vulnerable (15.2%)
  - RFC2822 date parsing (complex alternation)
  - Whitespace handling (nested quantifiers)
  - Format string processing (recursive patterns)

- **chalk**: 0/4 patterns vulnerable (0.0%)
  - Terminal styling library is ReDoS-safe

### Tool Evaluation Results
- **redos-detector**: 100% accuracy (recommended)
- **safe-regex**: 85.7% accuracy (misses complex cases)

## 🛡️ Mitigation Strategies

1. **Pattern Rewriting**: Simplify complex regex into safer alternatives
2. **RE2 Engine**: Use Google's RE2 for guaranteed linear-time execution
3. **Input Validation**: Limit input size and complexity
4. **Timeout Mechanisms**: Prevent infinite execution

## 📊 Technical Approach

- **Methodology**: Purposive sampling of popular JavaScript libraries
- **Detection**: Static analysis using redos-detector with 100% test accuracy
- **Validation**: Performance benchmarking with crafted malicious inputs
- **Scope**: JavaScript regex engine focused analysis

## ⚡ Installation & Dependencies

### Prerequisites
- Node.js (v14 or higher)
- npm (comes with Node.js)

### Quick Setup
```bash
# Clone/download the project
cd Project/

# Install all dependencies
npm install
```

### Dependencies Installed
- **redos-detector** (^6.1.2) - Main ReDoS detection tool with 100% test accuracy
- **safe-regex** (^1.1.0) - Alternative detection tool for comparison
- **re2** (^1.20.9) - Google's RE2 engine for safe regex execution

### Verify Installation
```bash
# Test that dependencies work
npm run analyze

# Run complete pipeline
npm run pipeline
```

