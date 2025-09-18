#!/usr/bin/env python3
"""
Dependency Scanner for ML Projects
Scans for vulnerable dependencies and generates SBOM
"""

import json
import subprocess
import sys
import os
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import requests
import warnings
warnings.filterwarnings('ignore')

class DependencyScanner:
    """Scanner for ML project dependencies and vulnerabilities"""
    
    def __init__(self):
        self.vulnerability_db = {}
        self.sbom_data = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.4',
            'version': 1,
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'tools': [{
                    'vendor': 'Raidar',
                    'name': 'ML Dependency Scanner',
                    'version': '1.0.0'
                }],
                'component': {
                    'type': 'application',
                    'name': 'ML Project',
                    'version': '1.0.0'
                }
            },
            'components': [],
            'dependencies': []
        }
    
    def scan_requirements_file(self, requirements_path: str) -> Dict[str, Any]:
        """Scan a requirements.txt file for dependencies"""
        result = {
            'file': requirements_path,
            'dependencies': [],
            'vulnerabilities': [],
            'issues': []
        }
        
        try:
            with open(requirements_path, 'r') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse dependency
                dep_info = self._parse_dependency(line)
                if dep_info:
                    dep_info['line_number'] = line_num
                    result['dependencies'].append(dep_info)
                    
                    # Check for vulnerabilities
                    vulns = self._check_vulnerabilities(dep_info['name'], dep_info.get('version'))
                    if vulns:
                        result['vulnerabilities'].extend(vulns)
        
        except Exception as e:
            result['issues'].append({
                'type': 'error',
                'message': f'Error reading requirements file: {str(e)}',
                'severity': 'high'
            })
        
        return result
    
    def scan_environment_file(self, env_path: str) -> Dict[str, Any]:
        """Scan environment.yml or conda environment file"""
        result = {
            'file': env_path,
            'dependencies': [],
            'vulnerabilities': [],
            'issues': []
        }
        
        try:
            with open(env_path, 'r') as f:
                content = f.read()
            
            # Simple YAML parsing for dependencies
            in_deps = False
            for line_num, line in enumerate(content.split('\n'), 1):
                line = line.strip()
                
                if line.startswith('dependencies:'):
                    in_deps = True
                    continue
                
                if in_deps and line and not line.startswith('-') and not line.startswith('#'):
                    in_deps = False
                    continue
                
                if in_deps and line.startswith('- '):
                    dep_line = line[2:].strip()
                    dep_info = self._parse_dependency(dep_line)
                    if dep_info:
                        dep_info['line_number'] = line_num
                        result['dependencies'].append(dep_info)
                        
                        # Check for vulnerabilities
                        vulns = self._check_vulnerabilities(dep_info['name'], dep_info.get('version'))
                        if vulns:
                            result['vulnerabilities'].extend(vulns)
        
        except Exception as e:
            result['issues'].append({
                'type': 'error',
                'message': f'Error reading environment file: {str(e)}',
                'severity': 'high'
            })
        
        return result
    
    def scan_pip_freeze(self) -> Dict[str, Any]:
        """Scan currently installed packages using pip freeze"""
        result = {
            'source': 'pip_freeze',
            'dependencies': [],
            'vulnerabilities': [],
            'issues': []
        }
        
        try:
            # Run pip freeze
            process = subprocess.run([sys.executable, '-m', 'pip', 'freeze'], 
                                   capture_output=True, text=True, timeout=30)
            
            if process.returncode != 0:
                result['issues'].append({
                    'type': 'error',
                    'message': f'pip freeze failed: {process.stderr}',
                    'severity': 'high'
                })
                return result
            
            for line in process.stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                dep_info = self._parse_dependency(line)
                if dep_info:
                    result['dependencies'].append(dep_info)
                    
                    # Check for vulnerabilities
                    vulns = self._check_vulnerabilities(dep_info['name'], dep_info.get('version'))
                    if vulns:
                        result['vulnerabilities'].extend(vulns)
        
        except subprocess.TimeoutExpired:
            result['issues'].append({
                'type': 'error',
                'message': 'pip freeze timed out',
                'severity': 'medium'
            })
        except Exception as e:
            result['issues'].append({
                'type': 'error',
                'message': f'Error running pip freeze: {str(e)}',
                'severity': 'high'
            })
        
        return result
    
    def _parse_dependency(self, dep_line: str) -> Optional[Dict[str, Any]]:
        """Parse a dependency line into structured data"""
        # Remove comments
        dep_line = dep_line.split('#')[0].strip()
        if not dep_line:
            return None
        
        # Handle different formats
        if '==' in dep_line:
            name, version = dep_line.split('==', 1)
            operator = '=='
        elif '>=' in dep_line:
            name, version = dep_line.split('>=', 1)
            operator = '>='
        elif '<=' in dep_line:
            name, version = dep_line.split('<=', 1)
            operator = '<='
        elif '>' in dep_line:
            name, version = dep_line.split('>', 1)
            operator = '>'
        elif '<' in dep_line:
            name, version = dep_line.split('<', 1)
            operator = '<'
        elif '~=' in dep_line:
            name, version = dep_line.split('~=', 1)
            operator = '~='
        else:
            name = dep_line
            version = None
            operator = None
        
        name = name.strip()
        if version:
            version = version.strip()
        
        return {
            'name': name,
            'version': version,
            'operator': operator,
            'type': 'python'
        }
    
    def _check_vulnerabilities(self, package_name: str, version: Optional[str]) -> List[Dict[str, Any]]:
        """Check for known vulnerabilities in a package"""
        vulnerabilities = []
        
        # This is a simplified vulnerability check
        # In a real implementation, you would query databases like:
        # - PyPI Advisory Database
        # - CVE database
        # - GitHub Security Advisories
        # - Snyk database
        
        # Known vulnerable packages (example data)
        known_vulnerable = {
            'tensorflow': {
                'versions': ['<2.4.0'],
                'cves': ['CVE-2021-41197'],
                'severity': 'high',
                'description': 'TensorFlow vulnerability in saved model'
            },
            'numpy': {
                'versions': ['<1.19.0'],
                'cves': ['CVE-2021-33430'],
                'severity': 'medium',
                'description': 'NumPy buffer overflow vulnerability'
            },
            'pandas': {
                'versions': ['<1.3.0'],
                'cves': ['CVE-2021-35047'],
                'severity': 'medium',
                'description': 'Pandas deserialization vulnerability'
            }
        }
        
        if package_name.lower() in known_vulnerable:
            vuln_info = known_vulnerable[package_name.lower()]
            if version and self._version_matches(version, vuln_info['versions']):
                vulnerabilities.append({
                    'package': package_name,
                    'version': version,
                    'cves': vuln_info['cves'],
                    'severity': vuln_info['severity'],
                    'description': vuln_info['description'],
                    'source': 'internal_db'
                })
        
        return vulnerabilities
    
    def _version_matches(self, version: str, version_constraints: List[str]) -> bool:
        """Check if a version matches any of the constraints"""
        # Simplified version matching
        # In a real implementation, use proper semantic versioning
        for constraint in version_constraints:
            if constraint.startswith('<'):
                constraint_version = constraint[1:]
                if self._compare_versions(version, constraint_version) < 0:
                    return True
            elif constraint.startswith('>'):
                constraint_version = constraint[1:]
                if self._compare_versions(version, constraint_version) > 0:
                    return True
        
        return False
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings"""
        # Simplified version comparison
        # In a real implementation, use proper semantic versioning
        try:
            v1_parts = [int(x) for x in v1.split('.')]
            v2_parts = [int(x) for x in v2.split('.')]
            
            # Pad with zeros
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for i in range(max_len):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            
            return 0
        except:
            return 0
    
    def generate_sbom(self, scan_results: List[Dict[str, Any]], output_file: str):
        """Generate Software Bill of Materials (SBOM)"""
        components = []
        dependencies = []
        
        for result in scan_results:
            for dep in result.get('dependencies', []):
                component = {
                    'type': 'library',
                    'name': dep['name'],
                    'version': dep.get('version', 'unknown'),
                    'purl': f'pkg:pypi/{dep["name"]}@{dep.get("version", "unknown")}',
                    'properties': [
                        {
                            'name': 'dependency-type',
                            'value': dep.get('type', 'python')
                        }
                    ]
                }
                
                # Add vulnerability information
                vulns = [v for v in result.get('vulnerabilities', []) 
                        if v['package'] == dep['name']]
                if vulns:
                    component['vulnerabilities'] = vulns
                
                components.append(component)
                dependencies.append({
                    'ref': component['purl'],
                    'dependsOn': []
                })
        
        self.sbom_data['components'] = components
        self.sbom_data['dependencies'] = dependencies
        
        # Write SBOM to file
        with open(output_file, 'w') as f:
            json.dump(self.sbom_data, f, indent=2)
    
    def scan_project(self, project_path: str) -> Dict[str, Any]:
        """Scan an entire ML project for dependencies"""
        project_path = Path(project_path)
        results = {
            'project_path': str(project_path),
            'scan_timestamp': datetime.now().isoformat(),
            'files_found': [],
            'scan_results': [],
            'summary': {
                'total_dependencies': 0,
                'vulnerable_dependencies': 0,
                'high_severity_vulns': 0,
                'medium_severity_vulns': 0,
                'low_severity_vulns': 0
            }
        }
        
        # Look for dependency files
        dependency_files = [
            'requirements.txt',
            'requirements-dev.txt',
            'requirements-test.txt',
            'environment.yml',
            'environment.yaml',
            'conda.yml',
            'Pipfile',
            'pyproject.toml',
            'setup.py'
        ]
        
        found_files = []
        for dep_file in dependency_files:
            file_path = project_path / dep_file
            if file_path.exists():
                found_files.append(str(file_path))
        
        results['files_found'] = found_files
        
        # Scan each found file
        for file_path in found_files:
            if file_path.endswith('requirements.txt'):
                scan_result = self.scan_requirements_file(file_path)
            elif file_path.endswith(('.yml', '.yaml')):
                scan_result = self.scan_environment_file(file_path)
            else:
                # Skip other file types for now
                continue
            
            results['scan_results'].append(scan_result)
        
        # Also scan current environment
        pip_freeze_result = self.scan_pip_freeze()
        results['scan_results'].append(pip_freeze_result)
        
        # Calculate summary
        all_deps = set()
        all_vulns = []
        
        for scan_result in results['scan_results']:
            for dep in scan_result.get('dependencies', []):
                all_deps.add(dep['name'])
            
            for vuln in scan_result.get('vulnerabilities', []):
                all_vulns.append(vuln)
        
        results['summary']['total_dependencies'] = len(all_deps)
        results['summary']['vulnerable_dependencies'] = len(set(v['package'] for v in all_vulns))
        
        for vuln in all_vulns:
            severity = vuln.get('severity', 'low')
            if severity == 'high':
                results['summary']['high_severity_vulns'] += 1
            elif severity == 'medium':
                results['summary']['medium_severity_vulns'] += 1
            else:
                results['summary']['low_severity_vulns'] += 1
        
        return results


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="ML Dependency Scanner")
    parser.add_argument("path", help="Path to ML project directory")
    parser.add_argument("-o", "--output", help="Output file for scan results")
    parser.add_argument("--sbom", help="Generate SBOM file")
    parser.add_argument("-f", "--format", choices=['json', 'text'], 
                       default='text', help="Output format")
    
    args = parser.parse_args()
    
    scanner = DependencyScanner()
    results = scanner.scan_project(args.path)
    
    # Generate SBOM if requested
    if args.sbom:
        scanner.generate_sbom(results['scan_results'], args.sbom)
        print(f"SBOM generated: {args.sbom}")
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            if args.format == 'json':
                json.dump(results, f, indent=2)
            else:
                f.write(format_text_report(results))
    else:
        if args.format == 'json':
            print(json.dumps(results, indent=2))
        else:
            print(format_text_report(results))


def format_text_report(results: Dict[str, Any]) -> str:
    """Format scan results as text report"""
    report = []
    report.append("=" * 60)
    report.append("ML DEPENDENCY SCAN REPORT")
    report.append("=" * 60)
    report.append(f"Project: {results['project_path']}")
    report.append(f"Scan Date: {results['scan_timestamp']}")
    report.append("")
    
    # Summary
    summary = results['summary']
    report.append("SUMMARY:")
    report.append(f"  Total Dependencies: {summary['total_dependencies']}")
    report.append(f"  Vulnerable Dependencies: {summary['vulnerable_dependencies']}")
    report.append(f"  High Severity Vulnerabilities: {summary['high_severity_vulns']}")
    report.append(f"  Medium Severity Vulnerabilities: {summary['medium_severity_vulns']}")
    report.append(f"  Low Severity Vulnerabilities: {summary['low_severity_vulns']}")
    report.append("")
    
    # Files found
    report.append("DEPENDENCY FILES FOUND:")
    for file_path in results['files_found']:
        report.append(f"  - {file_path}")
    report.append("")
    
    # Detailed results
    for scan_result in results['scan_results']:
        if scan_result.get('dependencies'):
            report.append(f"SOURCE: {scan_result.get('file', scan_result.get('source', 'unknown'))}")
            report.append("DEPENDENCIES:")
            
            for dep in scan_result['dependencies']:
                version_info = f" {dep['operator']} {dep['version']}" if dep.get('version') else ""
                report.append(f"  - {dep['name']}{version_info}")
            
            if scan_result.get('vulnerabilities'):
                report.append("VULNERABILITIES:")
                for vuln in scan_result['vulnerabilities']:
                    severity_icon = {
                        'high': '🔴',
                        'medium': '🟡',
                        'low': '🔵'
                    }.get(vuln['severity'], '❓')
                    
                    report.append(f"  {severity_icon} {vuln['package']} {vuln.get('version', '')}")
                    report.append(f"    CVEs: {', '.join(vuln.get('cves', []))}")
                    report.append(f"    Description: {vuln.get('description', 'N/A')}")
            
            report.append("")
    
    return "\n".join(report)


if __name__ == "__main__":
    main()
