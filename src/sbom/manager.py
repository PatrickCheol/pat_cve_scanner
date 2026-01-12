import json
import os
from typing import List
from datetime import datetime
from src.sbom.languages.base import Dependency, BaseLanguageScanner

# Will import specific languages dynamically or statically
from src.sbom.languages.java import JavaScanner
from src.sbom.languages.python import PythonScanner
from src.sbom.languages.php import PhpScanner

class SbomManager:
    def __init__(self, target_dir: str, language: str):
        self.target_dir = target_dir
        self.language = language

    def scan(self) -> List[Dependency]:
        dependencies = []
        scanners = []

        if self.language == "java" or self.language == "all":
            scanners.append(JavaScanner(self.target_dir))
        if self.language == "python" or self.language == "all":
            scanners.append(PythonScanner(self.target_dir))
        if self.language == "php" or self.language == "all":
            scanners.append(PhpScanner(self.target_dir))

        for scanner in scanners:
            try:
                deps = scanner.scan()
                dependencies.extend(deps)
            except Exception as e:
                print(f"[!] Error during {scanner.__class__.__name__} scan: {e}")

        return dependencies

    def generate_cyclonedx(self, dependencies: List[Dependency], output_path: str):
        """
        Generates a minimal CycloneDX 1.4 JSON SBOM.
        """
        components = []
        for dep in dependencies:
            purl = f"pkg:{dep.type}/{dep.name}"
            if dep.version:
                purl += f"@{dep.version}"

            component = {
                "type": "library",
                "name": dep.name,
                "purl": purl
            }
            if dep.version:
                component["version"] = dep.version
            
            # Helper to distinguish guessed imports
            if dep.source == "code":
                 component["properties"] = [{"name": "detection_method", "value": "code_analysis"}]

            components.append(component)

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tool": {
                    "vendor": "PatScanner",
                    "name": "pat_scanner",
                    "version": "0.1.0"
                }
            },
            "components": components
        }

        with open(output_path, "w") as f:
            json.dump(sbom, f, indent=2)
        
        print(f"[*] SBOM generated at: {output_path}")
