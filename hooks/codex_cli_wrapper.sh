#!/bin/bash
# Wrapper script for Codex CLI hook that uses pipenv environment

# First check if pipenv is available
if ! command -v pipenv &> /dev/null; then
    echo "Error: pipenv is required but not found. Please install it with 'pip install pipenv'" >&2
    exit 0  # Exit 0 to not break Codex CLI, but print error
fi

# Check if this directory has a Pipfile
if [ ! -f "$(dirname "$0")/../Pipfile" ]; then
    echo "Error: Pipfile not found in parent directory" >&2
    exit 0  # Exit 0 to not break Codex CLI
fi

# Try to run the actual Python hook script via pipenv
cd "$(dirname "$0")/.."
if [ -f "hooks/codex_cli.py" ]; then
    RESULT=$(pipenv run python3 hooks/codex_cli.py 2>&1)
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo "$RESULT"
    else
        # If there was an error, pass it through but exit successfully to not break Codex
        if [ -n "$RESULT" ]; then
            echo "Error running codex hook: $RESULT" >&2
        fi
    fi
    
    # Always exit with success to not break Codex CLI even if hook fails
    exit 0
else
    echo "Error: hooks/codex_cli.py not found" >&2
    exit 0  # Exit 0 to not break Codex CLI
fi
