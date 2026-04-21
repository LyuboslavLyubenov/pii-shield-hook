#!/bin/bash
# Wrapper script for OpenCode hook that uses pipenv environment

# First check if pipenv is available
if ! command -v pipenv &> /dev/null; then
    echo "Error: pipenv is required but not found. Please install it with 'pip install pipenv'" >&2
    exit 0  # Exit 0 to not break OpenCode, but print error
fi

# Check if this directory has a Pipfile
if [ ! -f "$(dirname "$0")/../Pipfile" ]; then
    echo "Error: Pipfile not found in parent directory" >&2
    exit 0  # Exit 0 to not break OpenCode
fi

# Try to run the actual hook script via pipenv
cd "$(dirname "$0")/.."

if [ -f "hooks/opencode_hook.ts" ]; then
    # For TS plugin, make sure typescript tools are available in environment
    RESULT=$(pipenv run node --eval "console.log('Typescript plugin environment OK')" 2>/dev/null || echo "TS environment check failed")
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -eq 0 ]; then
        # For now, just validate that environment is working
        echo "{}"  # No specific output needed when environment is ready
    else
        echo "Error: Typescript environment not properly set up in pipenv" >&2
    fi
else
    echo "Error: hooks/opencode_hook.ts not found" >&2
fi

exit 0  # Always exit with success to not break OpenCode
