# PII Shield with Virtual Environment Support

This project extends the existing PII Shield to support virtual environments through pipenv for enhanced isolation and dependency management.

## Overview

PII Shield intercepts Claude Code, Codex CLI, and OpenCode tool calls (like Read, Bash, Grep) and incoming user prompts to detect and mask PII (Personally Identifiable Information) and secrets before they reach the LLM. This prevents sensitive information from leaking to cloud LLMs.

## Key Improvements with Virtual Environments

1. **Package Isolation**: Dependencies are contained within a dedicated virtual environment using pipenv
2. **Reproducible Builds**: With Pipfile.lock, installations on different machines will have identical dependencies
3. **Conflict Prevention**: No conflicts with other Python projects' dependencies
4. **Better Maintenance**: Easier to upgrade or downgrade Python packages consistently
5. **Hybrid Detection Modes**: Support for both regex-only and full NER detection based on context to minimize false positives

## Supported Tools

| Tool | Hook Type | Plugin Location | Detection Mode |
|------|-----------|-----------------|----------------|
| Claude Code | PreToolUse, UserPromptSubmit | `~/.claude/hooks/` | Context-aware |
| Codex CLI | PreToolUse, UserPromptSubmit | `~/.codex/plugins/` | Context-aware |
| OpenCode | tool.execute.before/after | `.opencode/plugins/` (project) or `~/.config/opencode/plugins/` (global) | Dual-hook system with content scanning |

## PII Content Scanning Capability

The system now supports comprehensive PII content scanning for file reading operations:

### File Content Scanning
- **OpenCode plugin** uses `tool.execute.after` hooks to scan actual file content returned by `read` operations
- **Content analysis** detects PII in file text (SSN, emails, credit cards, etc.) not just in file paths
- **File results** are redacted in-place if PII is detected, replacing sensitive content with placeholders like `<SSN_1>`, `<EMAIL_2>`
- **Support for multiple tools** - also scans command output from `bash` and search results from `grep` if they contain PII

### Tool Argument vs Content Scanning
- **`tool.execute.before`**: Uses regex_only mode to scan tool arguments/paths (prevents false positives from usernames in file paths)
- **`tool.execute.after`**: Uses full NER detection to scan actual tool results and file content (detects real PII)

### Testing Procedures
To verify the content scanning capability:
1. Create test files with PII content (emails, credit cards, SSNs)  
2. Use OpenCode `read` tool to load these files
3. Confirm PII content is replaced with appropriate placeholders in the returned content

## Context-Aware Detection

The system uses different detection modes based on the scanning context:

- **Regex-Only Mode**: Used for scanning file paths and tool arguments to avoid false positives (e.g., `/Users/username/` would not trigger USERNAME detection)  
- **Full NER Mode**: Used for scanning user prompts and tool results where real PII might be present (names, emails, etc.)

**Detection Strategies by Event Type:**
- `PreToolUse` events: Uses regex_only for tool arguments  
- `UserPromptSubmit` events: Uses full NER detection for user input
- `PostToolResult` events: Uses full NER for tool outputs/content

## Architecture

The system consists of:

1. `pii_shield.py` - Core PII/secret detection engine with regex_only mode support
2. `hooks/*.py` - Individual hooks for Claude Code and Codex CLI
3. `.opencode/plugins/pii-shield.ts` - OpenCode plugin (TypeScript) with dual-hook support
4. `hooks/*_wrapper.sh` - Shell wrappers that execute hooks in the pipenv environment
5. `Pipfile` - pipenv specification of dependencies
6. `opencode.json` - OpenCode configuration with plugin reference
7. Scripts in `scripts/` - Environment management utilities

## OpenCode Plugin

The OpenCode plugin uses the correct plugin format per [OpenCode docs](https://opencode.ai/docs/plugins):

```typescript
export const PIIShield = async ({ project, client, $, directory, worktree }) => {
  return {
    'tool.execute.before': async (input, output) => {
      // Check input.tool and scan output.args for PII using regex_only mode
      // Throw error to block execution if PII detected
    },
    'tool.execute.after': async (input, output) => {
      // Check output.results for PII in file content using full NER mode
      // Return redacted content if PII detected
    },
  };
};
```

The plugin implements both `tool.execute.before` and `tool.execute.after` hooks for comprehensive scanning:

- **`tool.execute.before`**: Scans tool arguments (file paths, command strings) using regex_only mode to prevent false positives from user paths
- **`tool.execute.after`**: Scans actual results (file content, command output) using full NER detection to catch PII in content itself
- **Supported tools**: `read`, `bash`, `grep` - each handled appropriately to check different content types

The plugin is loaded from:
- `.opencode/plugins/` (project-level, recommended) 
- `~/.config/opencode/plugins/` (global)

**Note**: `~/.opencode/plugins/` is NOT a valid plugin location for OpenCode.

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
