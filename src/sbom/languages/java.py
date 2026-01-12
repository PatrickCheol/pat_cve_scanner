import os
import re
from typing import List
from src.sbom.languages.base import BaseLanguageScanner, Dependency

class JavaScanner(BaseLanguageScanner):
    def scan(self) -> List[Dependency]:
        dependencies = []
        dependencies.extend(self._scan_gradle())
        dependencies.extend(self._scan_maven_pom()) # Optional support
        dependencies.extend(self._scan_code_imports(dependencies))
        return dependencies

    def _scan_gradle(self) -> List[Dependency]:
        found_deps = []
        gradle_files = []
        for root, dirs, files in os.walk(self.target_dir):
            for file in files:
                if file in ["build.gradle", "build.gradle.kts"]:
                    gradle_files.append(os.path.join(root, file))

        # Basic regex to capture group:name:version
        # implementation 'group:name:version'
        # implementation("group:name:version")
        # api "group:name:version"
        dependency_pattern = re.compile(r"""['"]([a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+(?::[a-zA-Z0-9._-]+)?)['"]""")
        
        for g_file in gradle_files:
            try:
                with open(g_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    matches = dependency_pattern.findall(content)
                    for match in matches:
                        parts = match.split(':')
                        group = parts[0]
                        name = parts[1]
                        version = parts[2] if len(parts) > 2 else None
                        
                        # Use group:name as the component name for maven coordinates
                        full_name = f"{group}:{name}"
                        found_deps.append(Dependency(name=full_name, version=version, type="maven", source="manifest"))
            except Exception as e:
                print(f"[!] Error reading {g_file}: {e}")
        
        return found_deps

    def _scan_maven_pom(self) -> List[Dependency]:
        # Placeholder for pom.xml support
        return []

    def _scan_code_imports(self, existing_deps: List[Dependency]) -> List[Dependency]:
        """
        Scans .java files for imports. 
        If an import doesn't belong to java.*, javax.*, or the project's own packages,
        and isn't covered by existing deps, add it as a potential dependency.
        """
        # This is heuristics-heavy.
        # We need to know "what packages does a dependency provide?" -> Hard without a DB.
        # User requested: "check imports and list things NOT in gradle"
        
        # 1. Collect all package prefixes from existing deps (Guessing)
        # e.g. "com.google.guava:guava" -> "com.google.guava"?? Not always true.
        # So checking "is it covered" is hard. We will list unique top-level domains found.
        
        found_imports = set()
        project_packages = set()

        # Pass 1: Identify project packages
        for root, dirs, files in os.walk(self.target_dir):
            for file in files:
                if file.endswith(".java"):
                    path = os.path.join(root, file)
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            for line in f:
                                line = line.strip()
                                if line.startswith("package "):
                                    # package com.mycompany.app;
                                    pkg = line.replace("package ", "").replace(";", "")
                                    project_packages.add(pkg)
                                    break
                    except:
                        pass
                        
        # Pass 2: Collect imports
        for root, dirs, files in os.walk(self.target_dir):
            for file in files:
                if file.endswith(".java"):
                    path = os.path.join(root, file)
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            for line in f:
                                line = line.strip()
                                if line.startswith("import "):
                                    # import com.google.common.lists;
                                    imp = line.replace("import ", "").replace(";", "").replace("static ", "")
                                    # Remove class name to get package
                                    # However, sometimes we want the full thing. Let's take the first 2-3 segments as a "library candidate"
                                    
                                    if imp.startswith("java.") or imp.startswith("javax."):
                                        continue
                                    
                                    # Check if it belongs to project
                                    is_internal = False
                                    for pp in project_packages:
                                        if imp.startswith(pp):
                                            is_internal = True
                                            break
                                    if is_internal:
                                        continue
                                    
                                    # It's an external library import
                                    # Heuristic: Take first 2 parts (e.g. org.apache) or 3 parts depending on commonality?
                                    # Let's take the full package name found for now, user can filter.
                                    # Actually, OSV scanner works on PACKAGES. "import org.apache.commons.lang3.StringUtils" -> "org.apache.commons:commons-lang3" ??
                                    # Without a resolution DB, mapping Import -> PURL is impossible accurately locally.
                                    # We will report it as a "detected_import" component with no version.
                                    
                                    # Let's try to group by top level domain to avoid noise
                                    # e.g. "com.google.common..."
                                    parts = imp.split('.')
                                    if len(parts) >= 2:
                                        candidate = f"{parts[0]}.{parts[1]}"
                                        found_imports.add(candidate)
                    except:
                        pass
        
        # Filter out what we might have found in Gradle?
        # Gradle gave us "group:name".
        # We can try to see if "group" matches "candidate".
        
        new_deps = []
        for imp in found_imports:
            covered = False
            for dep in existing_deps:
                # dep.name is "group:name"
                if dep.name.startswith(imp):
                    covered = True
                    break
            
            if not covered:
                # Add as a potential missing dependency
                # We don't have a version, so OSV scanner might skip it or check all versions.
                # OSV scanner usually needs PURLs with Namespace/Name.
                # We'll treat 'imp' as the name.
                new_deps.append(Dependency(name=imp, version=None, type="maven", source="code"))
                
        return new_deps
