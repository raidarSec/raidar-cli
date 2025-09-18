#!/usr/bin/env python3
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
