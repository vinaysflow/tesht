# Contributing to Tesht (Pramana)

Thank you for your interest in contributing to Tesht (Pramana).

## Code of Conduct

This project adheres to the [Contributor Covenant v2.1](CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code.

## License

By contributing, you agree that your contributions will be licensed under
the AGPL-3.0 License (the project's license). See [LICENSE](LICENSE) for
full terms.

## Contributor License Agreement (CLA)

All contributors must sign a Contributor License Agreement (CLA) before
their contributions can be merged. The CLA is based on the Apache
Individual Contributor License Agreement and grants Aurvia Global the
right to relicense contributions under commercial licenses (in addition
to AGPL-3.0).

To sign the CLA, contact: vinay@aurviaglobal.com

The CLA does not transfer copyright. Contributors retain copyright to
their contributions; they grant Aurvia Global a license for use under
AGPL-3.0 and commercial terms.

## Development Setup

See [README.md](README.md) for build and test instructions.

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes with accompanying tests
4. Ensure all tests pass (`pytest backend/tests/` and equivalent for
   gateway/, idp_bridge/, sdk/python/)
5. Sign your commits with GPG (we require signed commits on `main`)
6. Submit a pull request with a clear description of the change
7. Wait for review

## Reporting Issues

- **Bugs and feature requests:** Open a GitHub issue.
- **Security vulnerabilities:** See [SECURITY.md](SECURITY.md).
- **CLA questions:** Email vinay@aurviaglobal.com.

## Code Style

- Python: ruff (configured in CI)
- TypeScript: project conventions in `sdk/typescript/`
- Match existing code patterns; do not introduce new tooling without
  prior discussion

## Questions

Contact: vinay@aurviaglobal.com
