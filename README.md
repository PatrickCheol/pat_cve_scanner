# patXosv_scanner

**patXosv_scanner** is a lightweight CLI tool designed to generate a Software Bill of Materials (SBOM) from source code and scan it for vulnerabilities using Google's [osv-scanner](https://github.com/google/osv-scanner).

It uses a hybrid approach: parsing package manifests (like `build.gradle`, `requirements.txt`) AND analyzing source code imports to find unlisted or direct dependencies.

## Features

- **SBOM Generation**: Creates a CycloneDX 1.4 JSON SBOM.
- **Hybrid Detection**:
    - **Manifest Parsing**: Reads declared dependencies from build files.
    - **Code Analysis**: Scans source files for imports (`import ...`, `use ...`) to detect libraries that might be missing from manifests.
- **Vulnerability Scanning**: Automatically feeds the generated SBOM into `osv-scanner` to detect CVEs.
- **Multi-Language Support**:
    - **Java**: `build.gradle` parsing + `.java` import scanning.
    - **Python**: `requirements.txt` parsing + `.py` AST import scanning.
    - **PHP**: `composer.json` parsing + `.php` use statement scanning.

## Prerequisites

1. **Python 3.x**
2. **OSV-Scanner**: This tool relies on the `osv-scanner` binary.
   - Install via Go:
     ```bash
     go install github.com/google/osv-scanner/cmd/osv-scanner@latest
     ```
   - Or download from [Releases](https://github.com/google/osv-scanner/releases).
   - Ensure `osv-scanner` is in your system `PATH`.

## Installation

```bash
git clone https://github.com/yourusername/patXosv_scanner.git
cd patXosv_scanner
pip install -r requirements.txt
```

## Usage

Run the scanner by pointing it to your project directory.

```bash
python3 pat_scanner.py -t /path/to/your/project
```

### Options

- `-t, --target`: **(Required)** Path to the directory to scan.
- `-o, --output`: Path to save the generated SBOM JSON (default: `sbom.json`).
- `-l, --language`: Specific language to scan (`java`, `python`, `php`, `all`). Default is `all`.

### Example

```bash
# Scan the current directory
python3 pat_scanner.py -t .

# Scan a specific Python project and save SBOM to custom path
python3 pat_scanner.py -t ./my-app -l python -o my-app-sbom.json
```

## How if Works

1. **Scan Phase**: The tool iterates through the target directory.
    - It looks for manifest files (`requirements.txt`, etc.) to get exact versions.
    - It parses code files (`.py`, `.java`, etc.) to find imports. Imports not found in manifests are added as "detected via code" (versionless).
2. **SBOM Phase**: Consolidates findings into a CycloneDX JSON file.
3. **Audit Phase**: Executes `osv-scanner --sbom=sbom.json` and prints the vulnerability report to the console.

## License

MIT
