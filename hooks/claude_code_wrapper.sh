#!/bin/bash
# Wrapper script for Claude Code hook that uses pipenv environment

# First check if pipenv is available
if ! command -v pipenv &> /dev/null; then
    echo "Error: pipenv is required but not found. Please install it with 'pip install pipenv'" >&2
    exit 0  # Exit 0 to not break Claude Code, but print error
fi

# Check if this directory has a Pipfile
if [ ! -f "$(dirname "$0")/../Pipfile" ]; then
    echo "Error: Pipfile not found in parent directory" >&2
    exit 0  # Exit 0 to not break Claude Code
fi

# Run the actual Python hook script via pipenv, passing stdin
RESULT=$(cd "$(dirname "$0")/.." && pipenv run python3 hooks/claude_code.py)

# If pipenv command succeeded, output the result
if [ $? -eq 0 ]; then
    echo "$RESULT"
    exit 0
else
    echo "Error: Failed to execute claude_code.py in virtual environment" >&2
    exit 0  # Exit 0 to not break Claude Code even if hook fails
fi
