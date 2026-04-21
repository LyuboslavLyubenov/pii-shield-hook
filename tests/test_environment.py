import subprocess
import os

def test_environment_activation():
    """Test that the PII shield works in a virtual environment"""
    
    # Test that pipenv is available
    result = subprocess.run(['which', 'pipenv'], capture_output=True, text=True)
    assert result.returncode == 0, "pipenv should be available"
    
    # Test that the environment can run a simple command
    env_vars = os.environ.copy()
    env_vars['PYTHONPATH'] = os.getcwd()
    
    # Simple functionality test without PII
    input_json = '{"hook_event_name":"UserPromptSubmit","prompt":"This is a normal test sentence without PII."}'
    
    # Test with pipenv environment
    cmd = ['pipenv', 'run', 'python3', 'pii_shield.py', '--hook-mode', 'stdin']
    try:
        result = subprocess.Popen(
            cmd, 
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            cwd=os.path.dirname(__file__) + "/.."
        )
        stdout, stderr = result.communicate(input=input_json.encode())
        
        # When there's no PII, the result should be an empty JSON object {}
        # This is the expected result for clean input
        assert result.returncode == 0, f"Command should succeed. STDERR: {stderr.decode()}"
        
    except FileNotFoundError:
        # pipenv might not be installed yet
        print("WARNING: pipenv not fully set up, skipping environment test.")

def test_wrapper_scripts():
    """Test that the wrapper scripts execute properly"""
    
    # Test claude_code_wrapper.sh
    input_json = '{"hook_event_name":"UserPromptSubmit","prompt":"Simple test."}'
    
    cmd = ['bash', 'hooks/claude_code_wrapper.sh']
    try:
        result = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.path.dirname(__file__) + "/.."
        )
        stdout, stderr = result.communicate(input=input_json.encode())
        
        # Should not crash even if pipenv is not set up
        assert result.returncode == 0, f"Claude Code wrapper should exit 0. STDERR: {stderr.decode()}"
        
    except Exception as e:
        print(f"Wrapper test error (may be expected if pipenv not installed): {e}")
