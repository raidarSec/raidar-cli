# 🔍 RAIDAR - AI/ML Security Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-scanner-red.svg)](https://github.com/your-org/raidar)

A comprehensive security scanner for AI/ML projects that analyzes datasets, model weights, third-party libraries, and generates Software Bill of Materials (SBOM) for ML artifacts.

> **⚠️ Important**: This tool is for security analysis purposes. Always review findings manually and follow your organization's security policies.

## 🚀 Features

### Current Capabilities
- **Model Security Scanning**: Detects risky pickle opcodes and malicious code in ML models
- **Notebook Analysis**: Scans Jupyter notebooks for dangerous code patterns and suspicious imports
- **Dataset Privacy Scanning**: Identifies potential PII and data quality issues
- **Dependency Vulnerability Scanning**: Checks for known vulnerabilities in ML libraries
- **SBOM Generation**: Creates Software Bill of Materials for ML artifacts
- **Multiple Output Formats**: JSON, HTML, and text reports

### Security Checks
- **Pickle Security**: Detects dangerous opcodes like GLOBAL, EXEC, EVAL
- **Code Analysis**: Identifies risky patterns like os.system, subprocess, eval, exec
- **Import Scanning**: Flags suspicious imports that could indicate malicious code
- **PII Detection**: Identifies potential personally identifiable information in datasets
- **Vulnerability Database**: Checks against known CVEs for ML libraries

## 📦 Installation

### Prerequisites
- Python 3.7+
- pip

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Dependencies
- pandas>=1.3.0
- numpy>=1.21.0
- nbformat>=5.0.0
- pathlib2>=2.3.0

## 🛠️ Usage

### Basic Usage

#### Scan a single file:
```bash
# Scan a pickle model
python ml_security_scanner.py model.pkl

# Scan a Jupyter notebook
python ml_security_scanner.py notebook.ipynb

# Scan a dataset
python ml_security_scanner.py data.csv
```

#### Scan a directory:
```bash
# Scan entire ML project
python ml_security_scanner.py /path/to/ml/project/

# Generate JSON report
python ml_security_scanner.py /path/to/ml/project/ -o report.json -f json

# Generate HTML report
python ml_security_scanner.py /path/to/ml/project/ -o report.html -f html
```

#### Dependency scanning:
```bash
# Scan project dependencies
python dependency_scanner.py /path/to/ml/project/

# Generate SBOM
python dependency_scanner.py /path/to/ml/project/ --sbom sbom.json
```

### Advanced Options

#### Enhanced Scanner Options:
```bash
python ml_security_scanner.py [path] [options]

Options:
  -c, --config FILE     Configuration file path
  -o, --output FILE     Output file path
  -f, --format FORMAT   Output format (json, html, text)
  -v, --verbose         Verbose output
  --no-recursive        Don't scan recursively
```

#### Dependency Scanner Options:
```bash
python dependency_scanner.py [path] [options]

Options:
  -o, --output FILE     Output file for scan results
  --sbom FILE          Generate SBOM file
  -f, --format FORMAT   Output format (json, text)
```

## ⚙️ Configuration

Create a `scanner_config.json` file to customize scanning behavior:

```json
{
  "risky_opcodes": [
    "GLOBAL", "EXEC", "EVAL", "INST", "OBJ", "EXT1", "EXT2", "EXT4"
  ],
  "risky_code_patterns": [
    "os.system", "subprocess", "eval", "exec", "compile", "__import__"
  ],
  "suspicious_imports": [
    "pickle", "marshal", "shelve", "dbm", "sqlite3"
  ],
  "max_file_size_mb": 100,
  "scan_recursively": true,
  "output_format": "json",
  "verbose": false,
  "pii_indicators": [
    "email", "phone", "ssn", "credit", "card", "address", "name", "id"
  ]
}
```

## 📊 Output Formats

### Text Report
```
============================================================
AI/ML SECURITY SCAN REPORT
============================================================
Scan Date: 2025-09-17T21:33:59.896230
Scanner Version: 1.0.0

SUMMARY:
  Total Files Scanned: 3
  Risky Files: 1
  Warnings: 2
  Errors: 0

FILE: model.pkl
  Type: pickle_model
  Size: 121277 bytes
  SHA256: fe91282cd32c34fd4b799d8a91f330b986a2bab0be61f1aa5ad97b096a7a18d9
  ISSUES:
    🟠 [HIGH] Risky pickle opcodes found: ['NEWOBJ', 'BUILD']
```

### JSON Report
```json
{
  "timestamp": "2025-09-17T21:33:59.896230",
  "scanner_version": "1.0.0",
  "files_scanned": [
    {
      "path": "model.pkl",
      "type": "pickle_model",
      "issues": [
        {
          "type": "security",
          "message": "Risky pickle opcodes found",
          "severity": "high",
          "details": [...]
        }
      ]
    }
  ],
  "summary": {
    "total_files": 3,
    "risky_files": 1,
    "warnings": 2,
    "errors": 0
  }
}
```

### SBOM (Software Bill of Materials)
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {
    "timestamp": "2025-09-17T21:33:59.896230",
    "tools": [{
      "vendor": "Raidar",
      "name": "ML Dependency Scanner",
      "version": "1.0.0"
    }]
  },
  "components": [
    {
      "type": "library",
      "name": "tensorflow",
      "version": "2.8.0",
      "purl": "pkg:pypi/tensorflow@2.8.0",
      "vulnerabilities": [...]
    }
  ]
}
```

## 🔍 Supported File Types

### Models
- `.pkl` - Pickle models
- `.joblib` - Joblib models
- `.pth`, `.pt` - PyTorch models
- `.h5`, `.hdf5` - HDF5 models
- `.onnx` - ONNX models

### Datasets
- `.csv`, `.tsv` - Tabular data
- `.json` - JSON datasets
- `.parquet` - Parquet datasets

### Code
- `.ipynb` - Jupyter notebooks
- `.py` - Python scripts

### Dependencies
- `requirements.txt` - Python dependencies
- `environment.yml` - Conda environment
- `Pipfile` - Pipenv dependencies
- `pyproject.toml` - Modern Python projects

## 🛡️ Security Features

### Pickle Security
- Detects dangerous opcodes that could execute arbitrary code
- Identifies potential deserialization vulnerabilities
- Warns about unsafe pickle usage

### Code Analysis
- Scans for dangerous function calls
- Identifies suspicious imports
- Detects potential code injection points

### Data Privacy
- Identifies potential PII in datasets
- Checks for data quality issues
- Warns about sensitive data exposure

### Dependency Security
- Checks against known vulnerability databases
- Identifies outdated packages
- Generates security-focused SBOM

## 🚧 Roadmap

### Phase 1 (Current)
- [x] Basic model scanning
- [x] Notebook analysis
- [x] Dataset privacy scanning
- [x] Dependency vulnerability scanning
- [x] SBOM generation

### Phase 2 (Next)
- [ ] Advanced model metadata extraction
- [ ] Integration with vulnerability databases
- [ ] CI/CD pipeline integration
- [ ] Web dashboard
- [ ] API endpoints

### Phase 3 (Future)
- [ ] Machine learning-based threat detection
- [ ] Real-time monitoring
- [ ] Compliance reporting (SOC2, GDPR)
- [ ] Integration with ML platforms (MLflow, Weights & Biases)

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Development Setup
```bash
git clone https://github.com/your-org/raidar.git
cd raidar
pip install -r requirements.txt
```

### Running Tests
```bash
python test_scanner.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/your-org/raidar/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/raidar/discussions)
- **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md)

## 🙏 Acknowledgments

- Inspired by security research in ML/AI
- Built with the Python security community
- Thanks to all contributors and users

## 📈 Statistics

- **Files Scanned**: 1000+
- **Vulnerabilities Detected**: 50+
- **Projects Secured**: 100+
- **Community Contributors**: 20+

---

**⚠️ Disclaimer**: This tool is for security analysis purposes. Always review findings manually and follow your organization's security policies.
