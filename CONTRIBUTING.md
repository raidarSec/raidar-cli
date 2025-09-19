# Contributing to RAIDAR ML Security Scanner

Thank you for your interest in contributing to RAIDAR! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/raidar.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Install dependencies: `pip install -r requirements.txt`

## Development Setup

```bash
# Install development dependencies
pip install -r requirements.txt

# Run tests (generates test files automatically)
python test_scanner.py
```

## Code Style

- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Add docstrings to all functions and classes
- Keep functions focused and small

## Adding New Security Patterns

To add new security patterns:

1. Update `RISKY_CODE_PATTERNS` in `ml_security_scanner.py`
2. Add corresponding advice in `_get_actionable_advice()`
3. Update tests in `test_scanner.py`
4. Update documentation

## Testing

- All new features must include tests
- Run the test suite before submitting: `python test_scanner.py`
- Ensure tests pass for both safe and risky patterns

## Submitting Changes

1. Ensure all tests pass
2. Update documentation if needed
3. Commit your changes with clear messages
4. Push to your fork
5. Create a pull request with a clear description

## Security Considerations

- Never include actual malicious code in test files
- Use safe, controlled examples for testing
- Be careful when handling user-provided data

## Questions?

Feel free to open an issue for questions or discussions about the project.
