import argparse
import sys
import os

def parse_args():
    parser = argparse.ArgumentParser(description="patXosv_scanner: SBOM generator and Vulnerability Scanner")
    parser.add_argument(
        "-l", "--language", 
        required=False, 
        default="all",
        choices=["java", "python", "php", "all"],
        help="Target programming language to scan (default: all)"
    )
    parser.add_argument(
        "-t", "--target", 
        required=True, 
        help="Target directory to scan"
    )
    parser.add_argument(
        "-o", "--output", 
        default="sbom.json", 
        help="Output path for the generated SBOM JSON file"
    )
    
    return parser.parse_args()

def main():
    args = parse_args()
    
    target_dir = os.path.abspath(args.target)
    if not os.path.isdir(target_dir):
        print(f"Error: Target directory '{target_dir}' does not exist.")
        sys.exit(1)
        
    print(f"[*] Starting scan for language: {args.language}")
    print(f"[*] Target directory: {target_dir}")
    
    from src.sbom.manager import SbomManager
    from src.scanner.runner import OsvScannerRunner

    # 1. Generate SBOM
    manager = SbomManager(target_dir, args.language)
    dependencies = manager.scan()
    print(f"[*] Found {len(dependencies)} dependencies.")
    
    sbom_path = os.path.abspath(args.output)
    manager.generate_cyclonedx(dependencies, sbom_path)
    
    # 2. Run OSV Scanner
    runner = OsvScannerRunner()
    if not runner.check_installed():
        print("[!] osv-scanner not found. Skipping vulnerability scan.")
        print(f"[*] SBOM saved to {sbom_path}")
        return

    scan_results = runner.scan_sbom(sbom_path)
    runner.print_results(scan_results)
    
if __name__ == "__main__":
    main()
