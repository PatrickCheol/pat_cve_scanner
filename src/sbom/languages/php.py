import os
import json
import re
from typing import List
from src.sbom.languages.base import BaseLanguageScanner, Dependency

class PhpScanner(BaseLanguageScanner):
    def scan(self) -> List[Dependency]:
        dependencies = []
        dependencies.extend(self._scan_composer())
        dependencies.extend(self._scan_code_imports(dependencies))
        return dependencies

    def _scan_composer(self) -> List[Dependency]:
        found_deps = []
        composer_files = []
        for root, dirs, files in os.walk(self.target_dir):
            for file in files:
                if file == "composer.json":
                    composer_files.append(os.path.join(root, file))
        
        for c_file in composer_files:
            try:
                with open(c_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    require = data.get("require", {})
                    for pkg, ver in require.items():
                        if pkg == "php": continue
                        
                        # Packagist names are vendor/package
                        # Version clean up: ^1.2 -> 1.2
                        clean_ver = ver.replace('^', '').replace('~', '')
                        found_deps.append(Dependency(name=pkg, version=clean_ver, type="composer", source="manifest"))
            except Exception as e:
                print(f"[!] Error reading {c_file}: {e}")
        
        return found_deps

    def _scan_code_imports(self, existing_deps: List[Dependency]) -> List[Dependency]:
        """
        Scans .php files for 'use' statements.
        Tricky part: Mapping Namespace to Vendor/Package.
        e.g. use Monolog\Logger; -> monolog/monolog
        """
        found_namespaces = set()
        
        for root, dirs, files in os.walk(self.target_dir):
            for file in files:
                if file.endswith(".php"):
                    path = os.path.join(root, file)
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            # simple regex for 'use X;' or 'use X\Y;'
                            # use \Foo\Bar;
                            matches = re.findall(r'use\s+([a-zA-Z0-9_\\]+);', content)
                            for match in matches:
                                # Start with \ ? remove it
                                ns = match.lstrip('\\')
                                parts = ns.split('\\')
                                if len(parts) >= 2:
                                    # Vendor\Package candidate
                                    candidate = f"{parts[0]}/{parts[1]}".lower()
                                    found_namespaces.add(candidate)
                    except:
                        pass
        
        new_deps = []
        existing_names = {d.name.lower() for d in existing_deps}
        
        for ns in found_namespaces:
             # Heuristic: Filter out common internal things or non-libraries ??
             # Hard. But if it's not in composer.json, we list it.
             if ns not in existing_names:
                 new_deps.append(Dependency(name=ns, version=None, type="composer", source="code"))
                 
        return new_deps
