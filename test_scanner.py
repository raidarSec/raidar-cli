#!/usr/bin/env python3
"""
Test suite for Raidar ML Security Scanner
Creates test files and demonstrates scanner capabilities
"""

import os
import pickle
import tempfile
import json
from pathlib import Path
import pandas as pd
import numpy as np

def create_test_files():
    """Create test files for demonstrating scanner capabilities"""
    
    # Create temporary directory for test files
    test_dir = Path(tempfile.mkdtemp(prefix="raidar_test_"))
    print(f"Creating test files in temporary directory: {test_dir}")
    
    print("Creating test files for scanner demonstration...")
    
    # 1. Create a safe pickle model
    safe_model = {
        'model_type': 'linear_regression',
        'coefficients': [1.0, 2.0, 3.0],
        'intercept': 0.5,
        'feature_names': ['feature1', 'feature2', 'feature3']
    }
    
    with open(test_dir / "safe_model.pkl", "wb") as f:
        pickle.dump(safe_model, f)
    
    # 2. Create a potentially risky pickle (contains complex objects)
    risky_model = {
        'model_type': 'custom_model',
        'data': np.array([1, 2, 3, 4, 5]),
        'metadata': {
            'created_by': 'test_user',
            'version': '1.0.0',
            'description': 'Test model with complex structure'
        },
        'nested_data': {
            'level1': {
                'level2': {
                    'level3': [1, 2, 3, 4, 5]
                }
            }
        }
    }
    
    with open(test_dir / "risky_model.pkl", "wb") as f:
        pickle.dump(risky_model, f)
    
    # 3. Create a safe Jupyter notebook
    safe_notebook = {
        "cells": [
            {
                "cell_type": "markdown",
                "source": ["# Safe ML Notebook\n", "This notebook contains safe ML code."]
            },
            {
                "cell_type": "code",
                "source": [
                    "import pandas as pd\n",
                    "import numpy as np\n",
                    "from sklearn.linear_model import LinearRegression\n",
                    "\n",
                    "# Load data\n",
                    "data = pd.read_csv('data.csv')\n",
                    "X = data[['feature1', 'feature2']]\n",
                    "y = data['target']\n",
                    "\n",
                    "# Train model\n",
                    "model = LinearRegression()\n",
                    "model.fit(X, y)\n",
                    "\n",
                    "# Make predictions\n",
                    "predictions = model.predict(X)\n",
                    "print('Model trained successfully')"
                ],
                "outputs": []
            }
        ],
        "metadata": {},
        "nbformat": 4,
        "nbformat_minor": 4
    }
    
    with open(test_dir / "safe_notebook.ipynb", "w") as f:
        json.dump(safe_notebook, f, indent=2)
    
    # 4. Create a risky Jupyter notebook
    risky_notebook = {
        "cells": [
            {
                "cell_type": "markdown",
                "source": ["# Risky ML Notebook\n", "This notebook contains potentially dangerous code."]
            },
            {
                "cell_type": "code",
                "source": [
                    "import os\n",
                    "import subprocess\n",
                    "import pickle\n",
                    "\n",
                    "# Dangerous operations\n",
                    "os.system('echo \"This is dangerous!\"')\n",
                    "subprocess.run(['ls', '-la'])\n",
                    "\n",
                    "# Load untrusted pickle\n",
                    "with open('untrusted_model.pkl', 'rb') as f:\n",
                    "    model = pickle.load(f)\n",
                    "\n",
                    "# Use eval (dangerous)\n",
                    "user_input = input('Enter expression: ')\n",
                    "result = eval(user_input)\n",
                    "print(f'Result: {result}')"
                ],
                "outputs": []
            }
        ],
        "metadata": {},
        "nbformat": 4,
        "nbformat_minor": 4
    }
    
    with open(test_dir / "risky_notebook.ipynb", "w") as f:
        json.dump(risky_notebook, f, indent=2)
    
    # 5. Create a dataset with potential PII
    pii_data = pd.DataFrame({
        'user_id': [1, 2, 3, 4, 5],
        'email_address': ['user1@example.com', 'user2@example.com', 'user3@example.com', 'user4@example.com', 'user5@example.com'],
        'phone_number': ['555-1234', '555-5678', '555-9012', '555-3456', '555-7890'],
        'social_security': ['123-45-6789', '234-56-7890', '345-67-8901', '456-78-9012', '567-89-0123'],
        'credit_card': ['4111-1111-1111-1111', '4222-2222-2222-2222', '4333-3333-3333-3333', '4444-4444-4444-4444', '4555-5555-5555-5555'],
        'age': [25, 30, 35, 40, 45],
        'income': [50000, 60000, 70000, 80000, 90000]
    })
    
    pii_data.to_csv(test_dir / "pii_dataset.csv", index=False)
    
    # 6. Create a clean dataset
    clean_data = pd.DataFrame({
        'feature1': np.random.randn(100),
        'feature2': np.random.randn(100),
        'feature3': np.random.randn(100),
        'target': np.random.randn(100)
    })
    
    clean_data.to_csv(test_dir / "clean_dataset.csv", index=False)
    
    # 7. Create a requirements.txt with some dependencies
    requirements_content = """# ML Dependencies
numpy>=1.21.0
pandas>=1.3.0
scikit-learn>=1.0.0
tensorflow>=2.8.0
torch>=1.12.0
matplotlib>=3.5.0
seaborn>=0.11.0
jupyter>=1.0.0
notebook>=6.4.0
ipykernel>=6.0.0
"""
    
    with open(test_dir / "requirements.txt", "w") as f:
        f.write(requirements_content)
    
    # 8. Create a Python script with risky code
    risky_script_content = '''#!/usr/bin/env python3
"""
Risky Python script for testing
"""

import os
import subprocess
import pickle
import sys

def dangerous_function():
    """This function contains dangerous operations"""
    # System command execution
    os.system("echo 'This is dangerous!'")
    
    # Subprocess execution
    result = subprocess.run(['whoami'], capture_output=True, text=True)
    print(f"Current user: {result.stdout}")
    
    # File operations
    with open('/etc/passwd', 'r') as f:
        content = f.read()
        print("System info accessed")
    
    # Pickle operations
    malicious_data = {'cmd': 'rm -rf /'}
    with open('malicious.pkl', 'wb') as f:
        pickle.dump(malicious_data, f)
    
    # Dynamic code execution
    user_code = input("Enter Python code to execute: ")
    exec(user_code)
    
    # Import from string
    module_name = input("Enter module name to import: ")
    __import__(module_name)

if __name__ == "__main__":
    dangerous_function()
'''
    
    with open(test_dir / "risky_script.py", "w") as f:
        f.write(risky_script_content)
    
    print(f"Test files created in {test_dir}/")
    print("Files created:")
    for file in test_dir.iterdir():
        print(f"  - {file.name}")
    
    return test_dir

def run_scanner_tests():
    """Run the scanner on test files"""
    
    test_dir = create_test_files()
    
    print("\n" + "="*60)
    print("RUNNING SCANNER TESTS")
    print("="*60)
    
    # Test 1: Scan safe pickle model
    print("\n1. Testing safe pickle model:")
    print("-" * 40)
    os.system(f"python ml_security_scanner.py {test_dir}/safe_model.pkl")
    
    # Test 2: Scan risky pickle model
    print("\n2. Testing risky pickle model:")
    print("-" * 40)
    os.system(f"python ml_security_scanner.py {test_dir}/risky_model.pkl")
    
    # Test 3: Scan safe notebook
    print("\n3. Testing safe notebook:")
    print("-" * 40)
    os.system(f"python ml_security_scanner.py {test_dir}/safe_notebook.ipynb")
    
    # Test 4: Scan risky notebook
    print("\n4. Testing risky notebook:")
    print("-" * 40)
    os.system(f"python ml_security_scanner.py {test_dir}/risky_notebook.ipynb")
    
    # Test 5: Scan PII dataset
    print("\n5. Testing PII dataset:")
    print("-" * 40)
    os.system(f"python ml_security_scanner.py {test_dir}/pii_dataset.csv")
    
    # Test 6: Scan clean dataset
    print("\n6. Testing clean dataset:")
    print("-" * 40)
    os.system(f"python ml_security_scanner.py {test_dir}/clean_dataset.csv")
    
    # Test 7: Scan risky Python script
    print("\n7. Testing risky Python script:")
    print("-" * 40)
    os.system(f"python ml_security_scanner.py {test_dir}/risky_script.py")
    
    # Test 8: Scan entire test directory
    print("\n8. Testing directory scan:")
    print("-" * 40)
    os.system(f"python ml_security_scanner.py {test_dir}/ -o test_scan_report.json -f json")
    
    # Test 9: Dependency scanning
    print("\n9. Testing dependency scanning:")
    print("-" * 40)
    os.system(f"python dependency_scanner.py {test_dir}/ -o dependency_report.json")
    
    print("\n" + "="*60)
    print("SCANNER TESTS COMPLETED")
    print("="*60)
    print(f"Check the generated reports:")
    print(f"  - test_scan_report.json")
    print(f"  - dependency_report.json")
    print(f"  - Test files were in {test_dir}/")
    
    # Clean up temporary test directory
    import shutil
    shutil.rmtree(test_dir)
    print(f"Cleaned up temporary test directory: {test_dir}")

def cleanup_test_files():
    """Clean up test files"""
    import shutil
    
    # Clean up report files
    for report_file in ["test_scan_report.json", "dependency_report.json", "scan_report.json"]:
        if Path(report_file).exists():
            Path(report_file).unlink()
            print(f"Cleaned up {report_file}")
    
    print("Note: Test files are created in temporary directories and cleaned up automatically")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "cleanup":
        cleanup_test_files()
    else:
        run_scanner_tests()
        
        print("\nTo clean up test files, run:")
        print("python test_scanner.py cleanup")
