# PII Shield with Virtual Environment Support

This project extends the existing PII Shield to support virtual environments through pipenv for enhanced isolation and dependency management.

## Overview

PII Shield intercepts Claude Code,Codex CLI, and OpenCode tool calls (like Read, Bash, Grep) and incoming user prompts to detect and mask PII (Personally Identifiable Information) and secrets before they reach the LLM. This prevents sensitive information from leaking to cloud LLMs.

## Key Improvements with Virtual Environments

1. **Package Isolation**: Dependencies are contained within a dedicated virtual environment using pipenv
2. **Reproducible Builds**: With Pipfile.lock, installations on different machines will have identical dependencies
3. **Conflict Prevention**: No conflicts with other Python projects' dependencies
4. **Better Maintenance**: Easier to upgrade or downgrade Python packages consistently

## Installation Methods

The project supports two installation methods:

### Option 1: Virtual Environment (Recommended)
Uses pipenv for isolated packaging:

```bash
# Install pipenv first: pip install pipenv (or brew install pipenv on Mac)

bash install.sh --venv --all        # Install for Claude Code, Codex and OpenCode
bash install.sh --venv --dev --all # Include development dependencies
bash install.sh --venv --claude-code  # Claude Code hooks only
```

### Option 2: Classic/Traditional
Original method using system packages:

```bash  
bash install.sh --classic --all        # Install for Claude Code, Codex and OpenCode
bash install.sh --all                 # Default - installs classic method
```

## Requirements

- Python 3.10+
- pip (for classic install) 
- pipenv (for venv install)  
- macOS, Linux, or WSL (Windows)

## Architecture

The system consists of:

1. `pii_shield.py` - Core PII/secret detection engine
2. `hooks/*.py` - Individual hooks for each CLI tool (Claude Code, Codex, OpenCode)
3. `hooks/*_wrapper.sh` - Shell wrappers that execute hooks in the pipenv environment
4. `Pipfile` - pipenv specification of dependencies
5. Scripts in `scripts/` - Environment management utilities

## Performance

The virtual environment does add a small overhead (typically <200ms) for the initial environment activation, but subsequent calls are efficient due to the pipenv caching mechanism.

## Troubleshooting

1. If Claude Code hooks do not activate, ensure the shell script wrappers have execute permissions:

```bash
chmod +x hooks/*_wrapper.sh
```

2. Pipenv might need shell configuration after install:

```bash  
pipenv --venv  # This will create/load the environment 
```

3. If you get import errors, try:

```bash
cd path/to/pii-shield
pipenv install
pipenv run python3 pii_shield.py --help
```
