import os
import re
import ast
from typing import List, Set
from src.sbom.languages.base import BaseLanguageScanner, Dependency

class PythonScanner(BaseLanguageScanner):
    def scan(self) -> List[Dependency]:
        dependencies = []
        dependencies.extend(self._scan_requirements())
        dependencies.extend(self._scan_code_imports(dependencies))
        return dependencies

    def _scan_requirements(self) -> List[Dependency]:
        found_deps = []
        req_files = []
        for root, dirs, files in os.walk(self.target_dir):
            for file in files:
                if file == "requirements.txt":
                    req_files.append(os.path.join(root, file))
        
        # Pattern for "package==version" or "package>=version" etc
        # Simply capturing the package name and strict version if '=='
        for r_file in req_files:
            try:
                with open(r_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        
                        # Strip comments at end of line
                        line = line.split('#')[0].strip()
                        
                        # Parse name and version
                        # Very naive parser
                        if '==' in line:
                            parts = line.split('==')
                            name = parts[0]
                            version = parts[1].split(';')[0].strip() # remove markers
                        elif '>=' in line:
                             parts = line.split('>=')
                             name = parts[0]
                             version = None # OSV might not handle range well without specific version in lockfile.
                             # But let's verify if we want to include "min version"
                             # For now, treat non-pinned as versionless
                        else:
                            # Just name, or <, >
                            name = re.split(r'[<>=!]', line)[0]
                            version = None
                            
                        found_deps.append(Dependency(name=name, version=version, type="pypi", source="manifest"))
            except Exception as e:
                print(f"[!] Error reading {r_file}: {e}")
                
        return found_deps

    def _scan_code_imports(self, existing_deps: List[Dependency]) -> List[Dependency]:
        """
        Uses AST to find all imports in python files.
        """
        imports = set()
        
        for root, dirs, files in os.walk(self.target_dir):
            for file in files:
                if file.endswith(".py"):
                    path = os.path.join(root, file)
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            tree = ast.parse(f.read())
                            for node in ast.walk(tree):
                                if isinstance(node, ast.Import):
                                    for alias in node.names:
                                        imports.add(alias.name.split('.')[0])
                                elif isinstance(node, ast.ImportFrom):
                                    if node.module:
                                        imports.add(node.module.split('.')[0])
                    except:
                        pass
        
        # Filter standard library
        # This list is not exhaustive, but better than nothing.
        std_lib = {
            "os", "sys", "re", "json", "math", "datetime", "time", "random", "logging", "typing",
            "collections", "itertools", "functools", "pathlib", "subprocess", "ast", "abc",
            "argparse", "unittest", "threading", "multiprocessing", "socket", "email", "shutil", 
            "glob", "platform", "signal", "tempfile", "io", "copy", "warnings", "traceback",
            "csv", "zipfile", "tarfile", "concurrent"
        }
        
        new_deps = []
        existing_names = {d.name.lower().replace('-', '_') for d in existing_deps}
        
        for imp in imports:
            if imp in std_lib:
                continue
            
            # Normalize import name for comparison (e.g. PyYAML provides yaml, but scanning finds yaml)
            # Without a DB, we assume import name == package name
            normalized_imp = imp.lower()
            
            if normalized_imp not in existing_names:
                new_deps.append(Dependency(name=imp, version=None, type="pypi", source="code"))
                
        return new_deps
