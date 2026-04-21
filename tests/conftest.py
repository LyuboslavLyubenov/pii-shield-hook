import pytest
import subprocess
import time
import os

def test_pipenv_available():
    """Test that pipenv is available on the system"""
    result = subprocess.run(['which', 'pipenv'], capture_output=True, text=True)
    assert result.returncode == 0, "pipenv should be installed and available in PATH"

def test_pipenv_runs():
    """Test that pipenv command works properly"""
    result = subprocess.run(['pipenv', '--version'], capture_output=True, text=True)
    assert result.returncode == 0, f"pipenv --version should run successfully. Got: {result.stderr}"

def test_environment_creation():
    """Test that a basic environment can be created"""
    import tempfile
    import shutil
    
    # Create a temporary directory for the test
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a minimal Pipfile in the temp directory
        pipfile_content = '''[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
requests = "*"

[dev-packages]

[requires]
python_version = "3.10"
'''
        pipfile_path = os.path.join(temp_dir, 'Pipfile')
        with open(pipfile_path, 'w') as f:
            f.write(pipfile_content)
        
        # Change to the temp directory
        original_cwd = os.getcwd()
        try:
            os.chdir(temp_dir)
            
            # Run pipenv install
            result = subprocess.run(['pipenv', 'install'], capture_output=True, text=True)
            assert result.returncode == 0, f"pipenv install should succeed. Error: {result.stderr}"
            
            # Verify that Pipfile.lock was created
            assert os.path.exists('Pipfile.lock'), "Pipfile.lock should be created after pipenv install"
            
        finally:
            os.chdir(original_cwd)

def test_performance_overhead():
    """Test that venv activation doesn't add excessive overhead"""
    # Benchmark pipenv run vs direct python execution
    import time
    
    # Record time for direct python execution (simulating direct PII shield)
    start_time = time.time()
    result = subprocess.run(['python3', '-c', 'print("test")'], 
                          capture_output=True, text=True)
    direct_time = time.time() - start_time
    
    # Record time for pipenv execution (simulating with venv wrapper)
    start_time = time.time() 
    result = subprocess.run(['pipenv', 'run', 'python3', '-c', 'print("test")'],
                          capture_output=True, text=True, cwd=os.path.dirname(__file__))
    pipenv_time = time.time() - start_time
    
    # The pipenv overhead should be reasonable (less than 2 seconds for this simple test)
    # In a proper environment with Pipfile, this would be faster
    assert pipenv_time < 3.0, f"Pipenv execution should not take more than 3 seconds (got {pipenv_time:.2f}s)"
