# OpenCode Plugin Installation

## Installation Instructions

To install the PII Shield plugin for OpenCode, follow these steps:

### Option 1: Automatic Installation (Recommended)

Run the install script:
```bash
bash install.sh --opencode
```

This will:
- Create `.opencode/plugins/pii-shield.ts` in your project
- Add the plugin to your `opencode.json` configuration
- Set up the Python backend path correctly

### Option 2: Manual Installation

1. Create the plugin directory in your project:
```bash
mkdir -p .opencode/plugins
```

2. Copy the plugin file to your project's `.opencode/plugins/` directory:
```bash
cp ./hooks/opencode_hook.ts .opencode/plugins/pii-shield.ts
```

3. Add the plugin to your project's `opencode.json`:
```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [
    "./.opencode/plugins/pii-shield.ts"
  ]
}
```

## Plugin Locations

OpenCode loads plugins from these directories:
- `.opencode/plugins/` - Project-level plugins (loaded per project)
- `~/.config/opencode/plugins/` - Global plugins (loaded for all projects)

**Note**: The old `~/.opencode/plugins/` directory is NOT supported by OpenCode.

## How It Works

The PII Shield plugin intercepts tool executions (`read`, `bash`, `grep`) before they are processed. It:

- Scans file paths before `read` operations (using regex_only mode to prevent false positives)
- Scans bash command strings before execution (with full detection when needed)
- Scans grep patterns and paths before searching
- Blocks execution if PII/secrets are detected

### Dual Hook System

The plugin implements both `tool.execute.before` and `tool.execute.after` hooks for comprehensive scanning:

**`tool.execute.before` hooks**
- **Purpose**: Scan tool arguments before tool is executed
- **Mode**: Uses regex_only scanning by default to prevent false positives from paths
- **Applies to**: File paths, command arguments like `/Users/username/project/`

**`tool.execute.after` hooks** 
- **Purpose**: Scan tool results/output after tool execution
- **Mode**: Uses full NER detection to find PII in results
- **Applies to**: File content from `read` tool, command output from `bash`

The plugin detects different hook events and uses appropriate scanning strategies:
- `PreToolUse`: Uses regex_only scanning for tool arguments/paths to prevent false positives
- `UserPromptSubmit`: Uses full NER detection for user-entered content including names/emails
- `PostToolResult`: Uses full NER detection for tool results and file content

The plugin uses the correct OpenCode plugin format:
```typescript
export const PIIShield = async ({ project, client, $, directory, worktree }) => {
  return {
    'tool.execute.before': async (input, output) => {
      // input.tool contains the tool name
      // output.args contains the tool arguments
      // Throw an error to block execution
    },
    'tool.execute.after': async (input, output) => {
      // input.tool contains the tool name
      // output contains the tool result
      // Return modified output to redact PII in results  
    }
  };
};
```

## Configuration 

The plugin uses a shared Python backend (`pii_shield.py`) for scanning operations. Requirements:
- Python 3.10+
- torch, transformers packages installed

## Testing

### Testing Within OpenCode Sessions

For verifying functionality within actual OpenCode sessions, use these test procedures:

**Test Commands with API Keys and Secrets:**
```bash
bash: echo "sk-test12345678901234567890"
```
Expected result: The command should be blocked with "PII Shield: PII/Secrets detected..."

**Test Reading Files with PII Content:**
1. Create test files with PII information:
   ```
   test_ssn.txt: Contains "123-45-6789"
   test_emails.txt: Contains "test@example.com"
   test_credit_cards.txt: Contains "4111111111111111"
   ```
2. Use OpenCode's read tool to load these files:
   ```
   read: ./tests/sample_tasks/task2_ssn.txt
   ```
Expected result: If file contains PII content (not just filename), it should be redacted with appropriate placeholders like `<SSN_1>` in the returned content.

**Test Different Context Handling:**
- File paths like `/Users/username/project/` should NOT be blocked (due to regex_only mode in before hook)
- Commands with real secrets like API keys SHOULD be blocked 
- PII content IN the file being read SHOULD be detected by after hook
- User prompts with personal information SHOULD be blocked (full NER mode)

**Verifying Hook Behavior:**
- `tool.execute.before` uses regex_only mode to prevent path false positives
- `tool.execute.after` uses full NER detection for content scanning
- Both hooks work together to provide comprehensive protection without false positives

## Troubleshooting

1. If the plugin doesn't load, verify the path in `opencode.json` matches the actual file location
2. Check that Python and dependencies are installed: `python3 -c "import torch; import transformers"`
3. Restart OpenCode after making changes to `opencode.json`