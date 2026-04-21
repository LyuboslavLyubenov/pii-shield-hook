# OpenCode Plugin Installation

## Installation Instructions

To install the PII Shield plugin for OpenCode, follow these steps:

1. Copy the plugin file `opencode_hook.ts` to your OpenCode plugins directory:
```bash
cp ./hooks/opencode_hook.ts ~/.opencode/plugins/
```

2. Add the plugin to your OpenCode configuration:
```json
{
  "plugins": [
    {
      "name": "pii-shield",
      "path": "~/.opencode/plugins/opencode_hook.ts",
      "enabled": true
    }
  ]
}
```

## How It Works

The PII Shield plugin intercepts all tool executions (`read`, `bash`, `grep`) and user prompts before they are processed by the LLM. It performs the following actions:

- Scans file contents during `read` operations
- Scans bash command output
- Scans grep results
- Scans user prompts
- Redacts any detected PII/secret information with type-safe placeholders

## Configuration 

The plugin uses a shared Python backend (`pii_shield.py`) for scanning operations. Make sure Python 3.10+ and the required dependencies (torch, transformers) are installed on your system.

For automatic setup, run:
```bash
./install.sh --opencode
```