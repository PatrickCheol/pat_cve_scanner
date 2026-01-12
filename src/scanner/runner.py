import subprocess
import json
import shutil
import sys

class OsvScannerRunner:
    def __init__(self):
        self.binary = shutil.which("osv-scanner")
        
    def check_installed(self) -> bool:
        return self.binary is not None

    def scan_sbom(self, sbom_path: str) -> dict:
        if not self.binary:
            raise RuntimeError("osv-scanner binary not found in PATH. Please install it first (e.g., 'go install github.com/google/osv-scanner/cmd/osv-scanner@latest').")

        print(f"[*] Running osv-scanner on {sbom_path}...")
        try:
            # Run osv-scanner --sbom=path --json
            result = subprocess.run(
                [self.binary, f"--sbom={sbom_path}", "--json"],
                capture_output=True,
                text=True
            )
            
            # osv-scanner returns non-zero exit code if vulnerabilities are found, but we want the JSON output regardless.
            output = result.stdout
            if not output:
                # If stdout is empty, maybe something went wrong or it printed to stderr?
                if result.stderr:
                    print(f"[!] osv-scanner stderr: {result.stderr}")
                return {}

            try:
                data = json.loads(output)
                return data
            except json.JSONDecodeError:
                print(f"[!] Failed to parse osv-scanner output. Raw output start: {output[:200]}...")
                return {}

        except Exception as e:
            print(f"[!] Check failed: {e}")
            return {}

    def print_results(self, scan_results: dict):
        results = scan_results.get("results", [])
        if not results:
            print("[+] No known vulnerabilities found (or scan failed).")
            return

        total_Vulns = 0
        for res in results:
            packages = res.get("packages", [])
            for pkg in packages:
                vulns = pkg.get("vulnerabilities", [])
                total_Vulns += len(vulns)
                pkg_info = pkg.get("package", {})
                print(f"\n[!] Package: {pkg_info.get('name')} {pkg_info.get('version', '')}")
                for v in vulns:
                    print(f"    - {v.get('id')}: {v.get('summary')}")
                    print(f"      Severity: {json.dumps(v.get('severity', []))}")
                    print(f"      Reference: {v.get('references', [{}])[0].get('url', 'N/A')}")
        
        print(f"\n[*] Total Vulnerabilities Found: {total_Vulns}")
