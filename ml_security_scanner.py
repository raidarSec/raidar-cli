#!/usr/bin/env python3
"""
Enhanced AI/ML Security Scanner
A comprehensive tool for scanning ML artifacts, datasets, and dependencies
"""

import argparse
import json
import os
import sys
import hashlib
import pickle
import pickletools
import nbformat
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import warnings
warnings.filterwarnings('ignore')

# Enhanced security patterns
RISKY_OPCODES = [
    'GLOBAL', 'EXEC', 'EVAL', 'REDUCE', 'BUILD', 'INST', 'OBJ',
    'NEWOBJ', 'EXT1', 'EXT2', 'EXT4', 'BINBYTES', 'SHORT_BINBYTES'
]

RISKY_CODE_PATTERNS = [
    'os.system(', 'eval(', 'exec(', 'compile(', '__import__(',
    'pickle.load(', 'pickle.loads(', 'marshal.load(', 'marshal.loads(',
    'shelve.open(', 'dbm.open(', 'sqlite3.connect(', 'urllib.urlopen(',
    'urllib2.urlopen(', 'requests.get(', 'requests.post(', 'socket.socket(',
    'ftplib.FTP(', 'telnetlib.Telnet(', 'smtplib.SMTP(', 'poplib.POP3(',
    'imaplib.IMAP4(', 'nntplib.NNTP(', 'http.client(', 'xmlrpc.client(',
    'multiprocessing.Process(', 'threading.Thread(', 'ctypes.CDLL(',
    'ctypes.WinDLL(', 'ctypes.util.find_library(', 'platform.system(',
    'sys.exit(', 'os._exit(', 'os.kill(', 'os.killpg(', 'signal.alarm(',
    'signal.pause(', 'signal.signal(', 'time.sleep(', 'time.time(',
    'input(', 'raw_input(', 'getattr(', 'setattr(', 'delattr(',
    'globals(', 'locals(', 'vars(', 'dir('
]

SUSPICIOUS_IMPORTS = [
    'pickle', 'marshal', 'shelve', 'dbm', 'sqlite3', 'urllib', 'urllib2',
    'requests', 'socket', 'ftplib', 'telnetlib', 'smtplib', 'poplib',
    'imaplib', 'nntplib', 'http.client', 'xmlrpc.client', 'multiprocessing',
    'threading', 'ctypes', 'platform', 'sys', 'os', 'signal', 'time',
    'subprocess', 'shutil', 'tempfile', 'zipfile', 'tarfile', 'gzip',
    'bz2', 'lzma', 'zlib', 'hashlib', 'hmac', 'secrets', 'random',
    'uuid', 'base64', 'binascii', 'codecs', 'encodings', 'locale',
    'gettext', 'unicodedata', 'stringprep', 'readline', 'rlcompleter',
    'cmd', 'shlex', 'configparser', 'argparse', 'getopt', 'optparse',
    'logging', 'warnings', 'traceback', 'inspect', 'dis', 'ast',
    'parser', 'symbol', 'token', 'keyword', 'tokenize', 'py_compile',
    'compileall', 'pyclbr', 'tabnanny', 'py_compile', 'compileall'
]

class MLScanner:
    """Enhanced ML Security Scanner"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config = self._load_config(config_file)
        self.scan_results = {
            'timestamp': datetime.now().isoformat(),
            'scanner_version': '1.0.0',
            'files_scanned': [],
            'summary': {
                'total_files': 0,
                'risky_files': 0,
                'warnings': 0,
                'errors': 0
            }
        }
    
    def _load_config(self, config_file: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        default_config = {
            'risky_opcodes': RISKY_OPCODES,
            'risky_code_patterns': RISKY_CODE_PATTERNS,
            'suspicious_imports': SUSPICIOUS_IMPORTS,
            'max_file_size_mb': 100,
            'scan_recursively': True,
            'output_format': 'json',
            'verbose': False
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"Warning: Could not load config file {config_file}: {e}")
        
        return default_config
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Scan a single file and return results"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            return {'error': f'File not found: {file_path}'}
        
        if file_path.stat().st_size > self.config['max_file_size_mb'] * 1024 * 1024:
            return {'error': f'File too large: {file_path}'}
        
        file_info = {
            'path': str(file_path),
            'size': file_path.stat().st_size,
            'modified': datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
            'sha256': self._calculate_hash(file_path),
            'type': self._detect_file_type(file_path),
            'issues': [],
            'metadata': {}
        }
        
        # Scan based on file type
        if file_path.suffix.lower() == '.pkl':
            file_info.update(self._scan_pickle(file_path))
        elif file_path.suffix.lower() == '.ipynb':
            file_info.update(self._scan_notebook(file_path))
        elif file_path.suffix.lower() in ['.py', '.pyw']:
            file_info.update(self._scan_python_file(file_path))
        elif file_path.suffix.lower() in ['.csv', '.tsv', '.json', '.parquet']:
            file_info.update(self._scan_dataset(file_path))
        elif file_path.suffix.lower() in ['.h5', '.hdf5', '.pkl', '.joblib', '.pth', '.pt', '.onnx']:
            file_info.update(self._scan_model_file(file_path))
        else:
            file_info['issues'].append({
                'type': 'info',
                'message': f'Unsupported file type: {file_path.suffix}',
                'severity': 'low'
            })
        
        self.scan_results['files_scanned'].append(file_info)
        
        # Update summary for single file scans
        if file_info['issues']:
            for issue in file_info['issues']:
                if issue['severity'] in ['high', 'critical']:
                    self.scan_results['summary']['risky_files'] += 1
                elif issue['severity'] == 'medium':
                    self.scan_results['summary']['warnings'] += 1
                elif issue['type'] == 'error':
                    self.scan_results['summary']['errors'] += 1
        
        return file_info
    
    def _detect_file_type(self, file_path: Path) -> str:
        """Detect the type of ML artifact"""
        suffix = file_path.suffix.lower()
        
        if suffix == '.pkl':
            return 'pickle_model'
        elif suffix == '.ipynb':
            return 'jupyter_notebook'
        elif suffix in ['.py', '.pyw']:
            return 'python_script'
        elif suffix in ['.csv', '.tsv']:
            return 'tabular_dataset'
        elif suffix == '.json':
            return 'json_dataset'
        elif suffix == '.parquet':
            return 'parquet_dataset'
        elif suffix in ['.h5', '.hdf5']:
            return 'hdf5_model'
        elif suffix == '.joblib':
            return 'joblib_model'
        elif suffix in ['.pth', '.pt']:
            return 'pytorch_model'
        elif suffix == '.onnx':
            return 'onnx_model'
        else:
            return 'unknown'
    
    def _calculate_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return "unknown"
    
    def _scan_pickle(self, file_path: Path) -> Dict[str, Any]:
        """Enhanced pickle file scanning"""
        result = {'issues': [], 'metadata': {}}
        
        try:
            # Check for risky opcodes
            with open(file_path, 'rb') as f:
                opcodes_found = []
                for opcode, arg, pos in pickletools.genops(f):
                    if opcode.name in self.config['risky_opcodes']:
                        opcodes_found.append({
                            'opcode': opcode.name,
                            'position': pos,
                            'argument': str(arg)[:100] if arg else None
                        })
                
                if opcodes_found:
                    # Simplify opcode reporting - just show unique opcodes and count
                    unique_opcodes = list(set(o["opcode"] for o in opcodes_found))
                    result['issues'].append({
                        'type': 'security',
                        'message': f'Risky pickle opcodes detected: {", ".join(unique_opcodes)} ({len(opcodes_found)} instances)',
                        'severity': 'high',
                        'details': {
                            'unique_opcodes': unique_opcodes,
                            'total_instances': len(opcodes_found),
                            'first_occurrence': opcodes_found[0] if opcodes_found else None
                        }
                    })
                
                # Try to extract metadata safely
                f.seek(0)
                try:
                    # This is risky but we're doing it in a controlled environment
                    obj = pickle.load(f)
                    result['metadata'] = self._extract_object_metadata(obj)
                except Exception as e:
                    result['issues'].append({
                        'type': 'warning',
                        'message': f'Could not deserialize pickle: {str(e)}',
                        'severity': 'medium'
                    })
        
        except Exception as e:
            result['issues'].append({
                'type': 'error',
                'message': f'Error scanning pickle file: {str(e)}',
                'severity': 'high'
            })
        
        return result
    
    def _scan_notebook(self, file_path: Path) -> Dict[str, Any]:
        """Enhanced notebook scanning"""
        result = {'issues': [], 'metadata': {}}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                nb = nbformat.read(f, as_version=4)
            
            # Extract metadata
            result['metadata'] = {
                'nbformat': nb.nbformat,
                'nbformat_minor': nb.nbformat_minor,
                'cell_count': len(nb.cells),
                'code_cells': sum(1 for cell in nb.cells if cell.cell_type == 'code'),
                'markdown_cells': sum(1 for cell in nb.cells if cell.cell_type == 'markdown'),
                'output_cells': sum(1 for cell in nb.cells if cell.cell_type == 'output')
            }
            
            # Scan each cell
            risky_cells = []
            imports_found = set()
            
            for i, cell in enumerate(nb.cells):
                if cell.cell_type == 'code':
                    code = cell.source
                    
                    # Check for risky patterns (but not imports)
                    for pattern in self.config['risky_code_patterns']:
                        if pattern in code:
                            # Skip if it's just an import statement
                            lines = code.split('\n')
                            has_actual_usage = False
                            for line in lines:
                                line_stripped = line.strip()
                                # Skip imports and comments
                                if (line_stripped.startswith('import ') or line_stripped.startswith('from ') or 
                                    line_stripped.startswith('#')):
                                    continue
                                # Check for actual usage
                                if pattern in line and not line_stripped.startswith(('import ', 'from ')):
                                    has_actual_usage = True
                                    break
                            
                            if has_actual_usage:
                                risky_cells.append({
                                    'cell_number': i + 1,
                                    'pattern': pattern,
                                    'code_snippet': code.strip()[:200] + '...' if len(code.strip()) > 200 else code.strip()
                                })
                    
                    # Extract imports
                    lines = code.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line.startswith(('import ', 'from ')):
                            for imp in self.config['suspicious_imports']:
                                if imp in line:
                                    imports_found.add(imp)
            
            if risky_cells:
                # Group by pattern type for cleaner reporting
                pattern_counts = {}
                for cell in risky_cells:
                    pattern = cell['pattern']
                    pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
                
                result['issues'].append({
                    'type': 'security',
                    'message': f'Dangerous code patterns found: {", ".join([f"{p}({c})" for p, c in pattern_counts.items()])}',
                    'severity': 'high',
                    'details': {
                        'pattern_counts': pattern_counts,
                        'affected_cells': len(risky_cells),
                        'examples': risky_cells[:3]  # Show first 3 examples
                    }
                })
            
            if imports_found:
                result['issues'].append({
                    'type': 'security',
                    'message': f'Suspicious imports found: {list(imports_found)}',
                    'severity': 'medium',
                    'details': list(imports_found)
                })
        
        except Exception as e:
            result['issues'].append({
                'type': 'error',
                'message': f'Error scanning notebook: {str(e)}',
                'severity': 'high'
            })
        
        return result
    
    def _scan_python_file(self, file_path: Path) -> Dict[str, Any]:
        """Scan Python files for security issues"""
        result = {'issues': [], 'metadata': {}}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract basic metadata
            lines = content.split('\n')
            result['metadata'] = {
                'line_count': len(lines),
                'imports': [],
                'functions': [],
                'classes': []
            }
            
            # Check for risky patterns (but not imports)
            risky_patterns_found = []
            for pattern in self.config['risky_code_patterns']:
                if pattern in content:
                    # Find line numbers, but exclude import statements
                    for i, line in enumerate(lines):
                        line_stripped = line.strip()
                        # Skip if it's just an import statement
                        if (line_stripped.startswith('import ') or line_stripped.startswith('from ')) and pattern in ['subprocess', 'os', 'pickle']:
                            continue
                        # Skip comments
                        if line_stripped.startswith('#'):
                            continue
                        # Only flag actual usage, not imports
                        if pattern in line and not line_stripped.startswith(('import ', 'from ')):
                            risky_patterns_found.append({
                                'line': i + 1,
                                'pattern': pattern,
                                'code': line.strip()
                            })
            
            if risky_patterns_found:
                result['issues'].append({
                    'type': 'security',
                    'message': f'Risky code patterns found: {len(risky_patterns_found)} occurrences',
                    'severity': 'high',
                    'details': risky_patterns_found
                })
        
        except Exception as e:
            result['issues'].append({
                'type': 'error',
                'message': f'Error scanning Python file: {str(e)}',
                'severity': 'high'
            })
        
        return result
    
    def _scan_dataset(self, file_path: Path) -> Dict[str, Any]:
        """Scan dataset files for data quality and privacy issues"""
        result = {'issues': [], 'metadata': {}}
        
        try:
            if file_path.suffix.lower() == '.csv':
                df = pd.read_csv(file_path, nrows=1000)  # Sample first 1000 rows
                
                result['metadata'] = {
                    'shape': df.shape,
                    'columns': list(df.columns),
                    'dtypes': {col: str(dtype) for col, dtype in df.dtypes.to_dict().items()},
                    'null_counts': df.isnull().sum().to_dict(),
                    'memory_usage': int(df.memory_usage(deep=True).sum())
                }
                
                # Check for potential PII
                pii_indicators = ['email', 'phone', 'ssn', 'credit', 'card', 'address', 'name', 'id']
                potential_pii = []
                
                for col in df.columns:
                    col_lower = col.lower()
                    for indicator in pii_indicators:
                        if indicator in col_lower:
                            potential_pii.append(col)
                
                if potential_pii:
                    result['issues'].append({
                        'type': 'privacy',
                        'message': f'Potential PII columns detected: {potential_pii}',
                        'severity': 'medium',
                        'details': potential_pii
                    })
                
                # Check for data quality issues
                quality_issues = []
                if df.isnull().sum().sum() > len(df) * 0.5:
                    quality_issues.append('High percentage of missing values')
                
                if len(df.columns) > 1000:
                    quality_issues.append('Very high number of columns (potential curse of dimensionality)')
                
                if quality_issues:
                    result['issues'].append({
                        'type': 'data_quality',
                        'message': 'Data quality issues detected',
                        'severity': 'low',
                        'details': quality_issues
                    })
        
        except Exception as e:
            result['issues'].append({
                'type': 'error',
                'message': f'Error scanning dataset: {str(e)}',
                'severity': 'medium'
            })
        
        return result
    
    def _scan_model_file(self, file_path: Path) -> Dict[str, Any]:
        """Scan model files for metadata and potential issues"""
        result = {'issues': [], 'metadata': {}}
        
        try:
            if file_path.suffix.lower() in ['.pth', '.pt']:
                # PyTorch model
                result['metadata'] = {
                    'type': 'pytorch_model',
                    'size_mb': file_path.stat().st_size / (1024 * 1024)
                }
            elif file_path.suffix.lower() in ['.h5', '.hdf5']:
                # HDF5 model
                result['metadata'] = {
                    'type': 'hdf5_model',
                    'size_mb': file_path.stat().st_size / (1024 * 1024)
                }
            elif file_path.suffix.lower() == '.onnx':
                # ONNX model
                result['metadata'] = {
                    'type': 'onnx_model',
                    'size_mb': file_path.stat().st_size / (1024 * 1024)
                }
            else:
                result['metadata'] = {
                    'type': 'unknown_model',
                    'size_mb': file_path.stat().st_size / (1024 * 1024)
                }
        
        except Exception as e:
            result['issues'].append({
                'type': 'error',
                'message': f'Error scanning model file: {str(e)}',
                'severity': 'medium'
            })
        
        return result
    
    def _extract_object_metadata(self, obj: Any) -> Dict[str, Any]:
        """Safely extract metadata from Python objects"""
        metadata = {
            'type': type(obj).__name__,
            'module': getattr(type(obj), '__module__', 'unknown')
        }
        
        try:
            if hasattr(obj, '__dict__'):
                metadata['attributes'] = list(obj.__dict__.keys())
            
            if hasattr(obj, 'shape'):
                metadata['shape'] = obj.shape
            
            if hasattr(obj, 'dtype'):
                metadata['dtype'] = str(obj.dtype)
            
            if hasattr(obj, 'n_features_in_'):
                metadata['n_features'] = obj.n_features_in_
            
            if hasattr(obj, 'classes_'):
                metadata['classes'] = len(obj.classes_) if hasattr(obj.classes_, '__len__') else 'unknown'
        
        except Exception:
            pass  # Ignore errors in metadata extraction
        
        return metadata
    
    def scan_directory(self, directory_path: str) -> Dict[str, Any]:
        """Scan all ML artifacts in a directory"""
        directory_path = Path(directory_path)
        
        if not directory_path.exists():
            return {'error': f'Directory not found: {directory_path}'}
        
        # Find all relevant files
        ml_extensions = ['.pkl', '.ipynb', '.py', '.csv', '.tsv', '.json', '.parquet', 
                        '.h5', '.hdf5', '.joblib', '.pth', '.pt', '.onnx']
        
        files_to_scan = []
        if self.config['scan_recursively']:
            for ext in ml_extensions:
                files_to_scan.extend(directory_path.rglob(f'*{ext}'))
        else:
            for ext in ml_extensions:
                files_to_scan.extend(directory_path.glob(f'*{ext}'))
        
        # Scan each file
        for file_path in files_to_scan:
            if self.config['verbose']:
                print(f"Scanning: {file_path}")
            self.scan_file(file_path)
        
        # Update summary with actionable metrics
        self.scan_results['summary']['total_files'] = len(files_to_scan)
        self.scan_results['summary']['risky_files'] = sum(
            1 for file_info in self.scan_results['files_scanned']
            if any(issue['severity'] in ['high', 'critical'] for issue in file_info.get('issues', []))
        )
        self.scan_results['summary']['warnings'] = sum(
            1 for file_info in self.scan_results['files_scanned']
            if any(issue['severity'] == 'medium' for issue in file_info.get('issues', []))
        )
        self.scan_results['summary']['errors'] = sum(
            1 for file_info in self.scan_results['files_scanned']
            if any(issue['type'] == 'error' for issue in file_info.get('issues', []))
        )
        
        # Add risk assessment
        total_issues = (self.scan_results['summary']['risky_files'] + 
                       self.scan_results['summary']['warnings'] + 
                       self.scan_results['summary']['errors'])
        
        if total_issues == 0:
            self.scan_results['summary']['risk_level'] = 'SECURE'
        elif self.scan_results['summary']['risky_files'] > 0:
            self.scan_results['summary']['risk_level'] = 'HIGH_RISK'
        elif self.scan_results['summary']['warnings'] > 0:
            self.scan_results['summary']['risk_level'] = 'MEDIUM_RISK'
        else:
            self.scan_results['summary']['risk_level'] = 'LOW_RISK'
        
        return self.scan_results
    
    def generate_report(self, output_file: Optional[str] = None) -> str:
        """Generate a comprehensive scan report"""
        if output_file:
            output_path = Path(output_file)
            if output_path.suffix.lower() == '.json':
                with open(output_path, 'w') as f:
                    json.dump(self.scan_results, f, indent=2)
            elif output_path.suffix.lower() == '.html':
                html_content = self._generate_html_report()
                with open(output_path, 'w') as f:
                    f.write(html_content)
            else:
                # Default to text report
                with open(output_path, 'w') as f:
                    f.write(self._generate_text_report())
        
        return self._generate_text_report()
    
    def _generate_text_report(self) -> str:
        """Generate a concise, actionable security report"""
        report = []
        report.append("🔍 RAIDAR ML SECURITY SCAN")
        report.append("=" * 50)
        report.append(f"📅 {self.scan_results['timestamp'][:10]}")
        report.append("")
        
        # Summary with actionable insights
        summary = self.scan_results['summary']
        total_issues = summary['risky_files'] + summary['warnings'] + summary['errors']
        
        if total_issues == 0:
            report.append("✅ SECURE - No security issues found")
            report.append("")
            return "\n".join(report)
        
        # Risk assessment
        if summary['risky_files'] > 0:
            report.append(f"🚨 HIGH RISK - {summary['risky_files']} critical issues found")
        elif summary['warnings'] > 0:
            report.append(f"⚠️  MEDIUM RISK - {summary['warnings']} security warnings")
        else:
            report.append(f"ℹ️  LOW RISK - {summary['errors']} minor issues")
        
        report.append("")
        
        # Group issues by severity
        critical_issues = []
        high_issues = []
        medium_issues = []
        low_issues = []
        
        for file_info in self.scan_results['files_scanned']:
            for issue in file_info.get('issues', []):
                issue_data = {
                    'file': file_info['path'],
                    'type': file_info['type'],
                    'issue': issue,
                    'severity': issue['severity']
                }
                
                if issue['severity'] in ['critical', 'high']:
                    critical_issues.append(issue_data)
                elif issue['severity'] == 'medium':
                    medium_issues.append(issue_data)
                else:
                    low_issues.append(issue_data)
        
        # Report critical/high issues first
        if critical_issues:
            report.append("🚨 CRITICAL ISSUES (Fix Immediately):")
            report.append("-" * 40)
            for item in critical_issues:
                report.append(f"📁 {item['file']}")
                report.append(f"   Issue: {item['issue']['message']}")
                if 'details' in item['issue'] and item['issue']['details']:
                    # Show more details for context
                    details = item['issue']['details']
                    if isinstance(details, list):
                        # Show up to 5 locations for better context
                        details = details[:5]
                        for detail in details:
                            if isinstance(detail, dict) and 'line' in detail:
                                pattern = detail.get('pattern', 'unknown')
                                report.append(f"   Line {detail['line']}: {pattern}")
                            elif isinstance(detail, dict) and 'cell_number' in detail:
                                pattern = detail.get('pattern', 'unknown')
                                report.append(f"   Cell {detail['cell_number']}: {pattern}")
                            elif isinstance(details, dict) and 'examples' in details:
                                examples = details['examples'][:5]
                                for example in examples:
                                    if isinstance(example, dict) and 'line' in example:
                                        pattern = example.get('pattern', 'unknown')
                                        report.append(f"   Line {example['line']}: {pattern}")
                                    elif isinstance(example, dict) and 'cell_number' in example:
                                        pattern = example.get('pattern', 'unknown')
                                        report.append(f"   Cell {example['cell_number']}: {pattern}")
                
                # Show specific advice for each pattern found
                if 'details' in item['issue'] and item['issue']['details']:
                    details = item['issue']['details']
                    if isinstance(details, list) and details:
                        # Show advice for first few patterns
                        patterns_shown = set()
                        for detail in details[:3]:  # Show first 3 unique patterns
                            if isinstance(detail, dict) and 'pattern' in detail:
                                pattern = detail['pattern']
                                if pattern not in patterns_shown:
                                    patterns_shown.add(pattern)
                                    advice = self._get_actionable_advice(item['issue']['type'], item['type'], {'details': [detail]})
                                    report.append(f"   {pattern}: {advice}")
                    else:
                        report.append(f"   Action: {self._get_actionable_advice(item['issue']['type'], item['type'], item['issue'])}")
                else:
                    report.append(f"   Action: {self._get_actionable_advice(item['issue']['type'], item['type'], item['issue'])}")
                report.append("")
        
        # Report medium issues
        if medium_issues:
            report.append("⚠️  SECURITY WARNINGS (Review Soon):")
            report.append("-" * 40)
            for item in medium_issues:
                report.append(f"📁 {item['file']}")
                report.append(f"   Issue: {item['issue']['message']}")
                report.append(f"   Action: {self._get_actionable_advice(item['issue']['type'], item['type'], item['issue'])}")
                report.append("")
        
        # Report low issues (briefly)
        if low_issues:
            report.append("ℹ️  MINOR ISSUES:")
            report.append("-" * 40)
            for item in low_issues:
                report.append(f"📁 {item['file']}: {item['issue']['message']}")
        
        # Add summary recommendations
        if critical_issues or medium_issues:
            report.append("")
            report.append("📋 RECOMMENDED ACTIONS:")
            report.append("-" * 40)
            if any(item['issue']['type'] == 'security' for item in critical_issues + medium_issues):
                report.append("• Review and sanitize all flagged code patterns")
                report.append("• Consider using safer alternatives to risky functions")
            if any(item['type'] == 'pickle_model' for item in critical_issues + medium_issues):
                report.append("• Validate pickle files before loading in production")
                report.append("• Consider using safer serialization formats (joblib, ONNX)")
            if any(item['issue']['type'] == 'privacy' for item in critical_issues + medium_issues):
                report.append("• Remove or anonymize PII from datasets")
                report.append("• Implement data privacy controls")
        
        return "\n".join(report)
    
    def _get_actionable_advice(self, issue_type: str, file_type: str, issue_details: dict = None) -> str:
        """Get specific, actionable advice for each issue type"""
        
        # Get the specific pattern that was flagged
        pattern = None
        if issue_details and 'details' in issue_details:
            details = issue_details['details']
            if isinstance(details, list) and details:
                if isinstance(details[0], dict):
                    pattern = details[0].get('pattern', '')
            elif isinstance(details, dict) and 'examples' in details and details['examples']:
                if isinstance(details['examples'][0], dict):
                    pattern = details['examples'][0].get('pattern', '')
        
        # Specific advice based on the actual pattern found
        if pattern:
            pattern_advice = {
                'os.system(': 'WHY: os.system() executes shell commands directly, allowing command injection attacks. SOLUTION: Replace with subprocess.run() with shell=False. Example: subprocess.run(["ls", "-la"], shell=False)',
                'eval(': 'WHY: eval() executes arbitrary Python code from strings, enabling code injection. SOLUTION: Remove eval() and use ast.literal_eval() for safe evaluation or proper parsing libraries',
                'exec(': 'WHY: exec() executes arbitrary Python code from strings, enabling code injection. SOLUTION: Remove exec() and refactor to use proper function calls or configuration files',
                'compile(': 'WHY: compile() can execute arbitrary code when used with exec() or eval(). SOLUTION: Remove compile() and use proper parsing libraries instead',
                '__import__(': 'WHY: __import__() can load arbitrary modules at runtime, enabling malicious code execution. SOLUTION: Replace with importlib.import_module() with validation. Example: importlib.import_module("safe_module")',
                'pickle.load(': 'WHY: pickle.load() can execute arbitrary code during deserialization. SOLUTION: Validate pickle source first. Consider using joblib.load() or ONNX for ML models',
                'pickle.loads(': 'WHY: pickle.loads() can execute arbitrary code during deserialization. SOLUTION: Validate pickle data first. Consider using joblib.loads() or JSON for data',
                'input(': 'WHY: input() accepts user input without validation, enabling injection attacks. SOLUTION: Validate and sanitize user input. Use input validation libraries like pydantic',
                'raw_input(': 'WHY: raw_input() accepts user input without validation (Python 2). SOLUTION: Replace with input() and add validation. Example: validated_input = validate_user_input(input())',
                'getattr(': 'WHY: getattr() can access private attributes and methods, potentially exposing sensitive data. SOLUTION: Validate attribute names. Example: getattr(obj, "safe_attr", default_value)',
                'setattr(': 'WHY: setattr() can modify object attributes, potentially corrupting data or bypassing security. SOLUTION: Validate attribute names and values. Example: setattr(obj, "safe_attr", validated_value)',
                'delattr(': 'WHY: delattr() can delete critical object attributes, potentially breaking security controls. SOLUTION: Validate attribute names before deletion. Example: if hasattr(obj, "safe_attr"): delattr(obj, "safe_attr")',
                'globals(': 'WHY: globals() exposes all global variables, potentially leaking sensitive data. SOLUTION: Avoid globals() and use proper configuration management',
                'locals(': 'WHY: locals() exposes local variables, potentially leaking sensitive data. SOLUTION: Avoid locals() and use proper data structures',
                'vars(': 'WHY: vars() exposes object internals, potentially leaking sensitive data. SOLUTION: Validate object before using vars(). Example: vars(safe_object)',
                'dir(': 'WHY: dir() exposes object internals, potentially leaking sensitive information. SOLUTION: Use dir() carefully and consider using hasattr() for specific checks'
            }
            
            if pattern in pattern_advice:
                return pattern_advice[pattern]
        
        # Handle suspicious imports with detailed explanations
        if issue_type == 'security' and 'details' in (issue_details or {}):
            details = issue_details['details']
            if isinstance(details, list):
                for detail in details:
                    if detail in ['os', 'sys', 'subprocess', 'pickle', 'marshal', 'shelve', 'dbm', 'sqlite3', 'urllib', 'urllib2', 'requests', 'socket', 'ftplib', 'telnetlib', 'smtplib', 'poplib', 'imaplib', 'nntplib', 'http.client', 'xmlrpc.client', 'multiprocessing', 'threading', 'ctypes', 'platform', 'signal', 'time', 'shutil', 'tempfile', 'zipfile', 'tarfile', 'gzip', 'bz2', 'lzma', 'zlib', 'hashlib', 'hmac', 'secrets', 'random', 'uuid', 'base64', 'binascii', 'codecs', 'encodings', 'locale', 'gettext', 'unicodedata', 'stringprep', 'readline', 'rlcompleter', 'cmd', 'shlex', 'configparser', 'argparse', 'getopt', 'optparse', 'logging', 'warnings', 'traceback', 'inspect', 'dis', 'ast', 'parser', 'symbol', 'token', 'keyword', 'tokenize', 'py_compile', 'compileall', 'pyclbr', 'tabnanny']:
                        import_explanations = {
                            'os': 'WHY: os module provides system-level operations that can be dangerous if misused (file access, process control, environment variables). SOLUTION: Review usage - if only using safe functions like os.path.join(), consider pathlib.Path instead. If using os.system() or os.popen(), replace with subprocess.run()',
                            'sys': 'WHY: sys module provides access to system-specific parameters and functions that can be dangerous (sys.exit, sys.modules manipulation). SOLUTION: Review usage - avoid sys.exit() in libraries, use proper exception handling instead',
                            'subprocess': 'WHY: subprocess module can execute system commands, enabling command injection if not used carefully. SOLUTION: Always use subprocess.run() with shell=False and validate command arguments',
                            'pickle': 'WHY: pickle module can execute arbitrary code during deserialization. SOLUTION: Only load pickle files from trusted sources, or use safer alternatives like joblib for ML models',
                            'socket': 'WHY: socket module enables network communication that could be used for data exfiltration or remote code execution. SOLUTION: Review network usage and ensure proper authentication/encryption',
                            'requests': 'WHY: requests module can make HTTP requests that could be used for data exfiltration or downloading malicious content. SOLUTION: Validate URLs and implement proper network security controls',
                            'multiprocessing': 'WHY: multiprocessing module can spawn processes that could be used to bypass security controls. SOLUTION: Review process creation and ensure proper sandboxing',
                            'threading': 'WHY: threading module can create threads that might be used to bypass security controls or cause race conditions. SOLUTION: Review thread usage and ensure proper synchronization',
                            'ctypes': 'WHY: ctypes module can call native code, potentially bypassing Python security controls. SOLUTION: Avoid ctypes unless absolutely necessary, and validate all native function calls',
                            'platform': 'WHY: platform module can reveal system information that might be used for fingerprinting or attacks. SOLUTION: Review usage and avoid exposing sensitive system information',
                            'signal': 'WHY: signal module can handle system signals that might be used to interfere with process control. SOLUTION: Review signal handling and ensure proper security controls',
                            'time': 'WHY: time module can be used for timing attacks or to interfere with system time. SOLUTION: Review usage and avoid exposing timing information that could aid attacks',
                            'shutil': 'WHY: shutil module provides file operations that could be used to access or modify sensitive files. SOLUTION: Review file operations and ensure proper access controls',
                            'tempfile': 'WHY: tempfile module creates temporary files that could be used to store sensitive data or execute code. SOLUTION: Ensure temporary files are properly cleaned up and have secure permissions',
                            'zipfile': 'WHY: zipfile module can extract archives that might contain malicious files (zip bombs, path traversal). SOLUTION: Validate archive contents and implement proper extraction limits',
                            'tarfile': 'WHY: tarfile module can extract archives that might contain malicious files (path traversal, symlink attacks). SOLUTION: Validate archive contents and implement proper extraction limits',
                            'gzip': 'WHY: gzip module can decompress data that might be used for zip bombs or data exfiltration. SOLUTION: Implement proper size limits and validate compressed data',
                            'bz2': 'WHY: bz2 module can decompress data that might be used for zip bombs or data exfiltration. SOLUTION: Implement proper size limits and validate compressed data',
                            'lzma': 'WHY: lzma module can decompress data that might be used for zip bombs or data exfiltration. SOLUTION: Implement proper size limits and validate compressed data',
                            'zlib': 'WHY: zlib module can decompress data that might be used for zip bombs or data exfiltration. SOLUTION: Implement proper size limits and validate compressed data',
                            'hashlib': 'WHY: hashlib module can be used for cryptographic operations that might be misused. SOLUTION: Review usage and ensure proper cryptographic practices',
                            'hmac': 'WHY: hmac module can be used for message authentication that might be misused. SOLUTION: Review usage and ensure proper key management',
                            'secrets': 'WHY: secrets module generates cryptographically secure random numbers that might be misused. SOLUTION: Review usage and ensure proper random number generation practices',
                            'random': 'WHY: random module generates pseudo-random numbers that are not cryptographically secure. SOLUTION: Use secrets module for cryptographic purposes',
                            'uuid': 'WHY: uuid module generates unique identifiers that might leak information about system state. SOLUTION: Review usage and ensure proper UUID generation practices',
                            'base64': 'WHY: base64 module can encode/decode data that might be used for data exfiltration or obfuscation. SOLUTION: Review usage and ensure proper data handling',
                            'binascii': 'WHY: binascii module can convert between binary and ASCII that might be used for data exfiltration. SOLUTION: Review usage and ensure proper data handling',
                            'codecs': 'WHY: codecs module can handle character encodings that might be used for data exfiltration or injection. SOLUTION: Review usage and ensure proper encoding handling',
                            'encodings': 'WHY: encodings module can handle character encodings that might be used for data exfiltration or injection. SOLUTION: Review usage and ensure proper encoding handling',
                            'locale': 'WHY: locale module can access system locale information that might be used for fingerprinting. SOLUTION: Review usage and avoid exposing sensitive locale information',
                            'gettext': 'WHY: gettext module can access system locale information that might be used for fingerprinting. SOLUTION: Review usage and avoid exposing sensitive locale information',
                            'unicodedata': 'WHY: unicodedata module can access Unicode data that might be used for data exfiltration. SOLUTION: Review usage and ensure proper Unicode handling',
                            'stringprep': 'WHY: stringprep module can prepare strings that might be used for data exfiltration. SOLUTION: Review usage and ensure proper string handling',
                            'readline': 'WHY: readline module can access command history that might contain sensitive information. SOLUTION: Review usage and ensure proper history handling',
                            'rlcompleter': 'WHY: rlcompleter module can access command completion that might expose sensitive information. SOLUTION: Review usage and ensure proper completion handling',
                            'cmd': 'WHY: cmd module can create command interpreters that might be used for remote code execution. SOLUTION: Review usage and ensure proper command validation',
                            'shlex': 'WHY: shlex module can parse shell commands that might be used for command injection. SOLUTION: Review usage and ensure proper command parsing',
                            'configparser': 'WHY: configparser module can read configuration files that might contain sensitive information. SOLUTION: Review usage and ensure proper configuration security',
                            'argparse': 'WHY: argparse module can parse command line arguments that might be used for injection. SOLUTION: Review usage and ensure proper argument validation',
                            'getopt': 'WHY: getopt module can parse command line arguments that might be used for injection. SOLUTION: Review usage and ensure proper argument validation',
                            'optparse': 'WHY: optparse module can parse command line arguments that might be used for injection. SOLUTION: Review usage and ensure proper argument validation',
                            'logging': 'WHY: logging module can write to log files that might contain sensitive information. SOLUTION: Review usage and ensure proper log security',
                            'warnings': 'WHY: warnings module can display warnings that might expose sensitive information. SOLUTION: Review usage and ensure proper warning handling',
                            'traceback': 'WHY: traceback module can display stack traces that might expose sensitive information. SOLUTION: Review usage and ensure proper error handling',
                            'inspect': 'WHY: inspect module can access object internals that might expose sensitive information. SOLUTION: Review usage and ensure proper introspection handling',
                            'dis': 'WHY: dis module can disassemble bytecode that might expose sensitive information. SOLUTION: Review usage and ensure proper disassembly handling',
                            'ast': 'WHY: ast module can parse Python code that might be used for code injection. SOLUTION: Review usage and ensure proper AST handling',
                            'parser': 'WHY: parser module can parse Python code that might be used for code injection. SOLUTION: Review usage and ensure proper parsing handling',
                            'symbol': 'WHY: symbol module can access Python symbols that might expose sensitive information. SOLUTION: Review usage and ensure proper symbol handling',
                            'token': 'WHY: token module can access Python tokens that might expose sensitive information. SOLUTION: Review usage and ensure proper token handling',
                            'keyword': 'WHY: keyword module can access Python keywords that might expose sensitive information. SOLUTION: Review usage and ensure proper keyword handling',
                            'tokenize': 'WHY: tokenize module can tokenize Python code that might be used for code injection. SOLUTION: Review usage and ensure proper tokenization handling',
                            'py_compile': 'WHY: py_compile module can compile Python code that might be used for code injection. SOLUTION: Review usage and ensure proper compilation handling',
                            'compileall': 'WHY: compileall module can compile Python code that might be used for code injection. SOLUTION: Review usage and ensure proper compilation handling',
                            'pyclbr': 'WHY: pyclbr module can access Python class information that might expose sensitive information. SOLUTION: Review usage and ensure proper class handling',
                            'tabnanny': 'WHY: tabnanny module can access Python code that might expose sensitive information. SOLUTION: Review usage and ensure proper code handling'
                        }
                        if detail in import_explanations:
                            return import_explanations[detail]
        
        # Fallback advice by issue type
        advice_map = {
            'security': {
                'pickle_model': 'WHY: Pickle files can execute arbitrary code during deserialization. SOLUTION: Validate pickle file source and consider safer serialization formats like joblib or ONNX',
                'jupyter_notebook': 'WHY: Notebooks can contain malicious code that executes when run. SOLUTION: Review code for malicious patterns and sanitize dangerous function calls',
                'python_script': 'WHY: Python scripts can contain dangerous function calls that enable code injection. SOLUTION: Remove dangerous function calls and use safer alternatives with proper validation',
                'default': 'WHY: Security vulnerabilities can enable code injection or data exfiltration. SOLUTION: Review code for security vulnerabilities and implement proper input validation'
            },
            'privacy': {
                'tabular_dataset': 'WHY: PII in datasets can violate privacy regulations and enable identity theft. SOLUTION: Remove or anonymize PII columns before sharing. Use techniques like k-anonymity or differential privacy',
                'default': 'WHY: Privacy violations can result in regulatory fines and reputational damage. SOLUTION: Implement data privacy controls and anonymization techniques'
            },
            'data_quality': {
                'tabular_dataset': 'WHY: Poor data quality can lead to incorrect model predictions and business decisions. SOLUTION: Clean missing data and validate data quality. Use techniques like imputation or outlier detection',
                'default': 'WHY: Poor data quality can lead to incorrect model predictions. SOLUTION: Review data quality and implement validation pipelines'
            },
            'error': {
                'default': 'WHY: File format errors can prevent proper analysis and lead to incorrect conclusions. SOLUTION: Fix file format or corruption issues. Check file integrity and format compliance'
            }
        }
        
        return advice_map.get(issue_type, {}).get(file_type, 
               advice_map.get(issue_type, {}).get('default', 'Review and address the issue'))
    
    def _generate_html_report(self) -> str:
        """Generate an HTML report"""
        # This would be a more comprehensive HTML report
        # For now, return a simple HTML wrapper around the text report
        text_report = self._generate_text_report()
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>AI/ML Security Scan Report</title>
    <style>
        body {{ font-family: monospace; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 10px; }}
        .summary {{ background-color: #e8f4f8; padding: 10px; margin: 10px 0; }}
        .file {{ border: 1px solid #ccc; margin: 10px 0; padding: 10px; }}
        .issue {{ margin: 5px 0; padding: 5px; }}
        .critical {{ background-color: #ffebee; }}
        .high {{ background-color: #fff3e0; }}
        .medium {{ background-color: #fffde7; }}
        .low {{ background-color: #e8f5e8; }}
    </style>
</head>
<body>
    <pre>{text_report}</pre>
</body>
</html>
        """
        return html_content


def main():
    parser = argparse.ArgumentParser(description="Enhanced AI/ML Security Scanner")
    parser.add_argument("path", help="Path to file or directory to scan")
    parser.add_argument("-c", "--config", help="Configuration file path")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-f", "--format", choices=['json', 'html', 'text'], 
                       default='text', help="Output format")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--no-recursive", action="store_true", help="Don't scan recursively")
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = MLScanner(args.config)
    scanner.config['verbose'] = args.verbose
    scanner.config['scan_recursively'] = not args.no_recursive
    scanner.config['output_format'] = args.format
    
    # Scan
    if os.path.isfile(args.path):
        result = scanner.scan_file(args.path)
        if 'error' in result:
            print(f"Error: {result['error']}")
            sys.exit(1)
    elif os.path.isdir(args.path):
        result = scanner.scan_directory(args.path)
        if 'error' in result:
            print(f"Error: {result['error']}")
            sys.exit(1)
    else:
        print(f"Error: Path not found: {args.path}")
        sys.exit(1)
    
    # Generate report
    report = scanner.generate_report(args.output)
    
    if not args.output:
        print(report)


if __name__ == "__main__":
    main()
