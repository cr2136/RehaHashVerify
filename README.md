# Forensic Hash Verifier

PowerShell-based utility for verifying cryptographic hashes of exported forensic evidence files and generating a structured verification report.

## Purpose

This tool is designed to:

- Calculate SHA-256 and MD5 hashes of selected files
- Compare calculated hashes against user-supplied expected values
- Record PASS/FAIL results
- Generate a plain-text verification report suitable for case documentation

The tool is intended to support verification of forensic exports from tools such as GrayKey, Cellebrite, and similar platforms.

## Features

- GUI interface
- Drag-and-drop file support
- SHA-256 and MD5 hashing
- Automatic report generation
- Overall verification status

## Requirements

- Windows
- PowerShell 5.1 or later
- .NET Framework (default on most Windows systems)

## Usage

1. Launch the script or compiled EXE
2. Select file(s) to verify
3. Enter expected hash values (if available)
4. Click Verify
5. Save generated report

## Disclaimer

This tool is provided "as-is" with no warranty or guarantee of fitness for any purpose.  
It is not an official government tool.  
Users are responsible for validating results and following their agency policies and procedures.

## License

MIT License
