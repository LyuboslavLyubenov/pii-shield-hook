#!/bin/bash

# Display version of Python for debugging
set -e  # Exit if any command fails

show_help() {
    echo "Usage: $0 [OPTION]"
    echo "Install PII Shield hooks for AI coding tools"
    echo ""
    echo "Options:"
    echo "  --claude-code    Install hook for Claude Code"
    echo "  --codex          Install hook for Codex CLI" 
    echo "  --opencode       Install plugin for OpenCode"
    echo "  --all            Install all hooks/plugins"
    echo "  --help           Show this help message"
    echo ""
}

# Function to check Python version
check_python_version() {
    echo "Checking Python version..."
    if ! command -v python3 &> /dev/null; then
        echo "Error: Python3 is not installed or not in PATH"
        exit 1
    fi

    local version_output=$(python3 --version 2>&1)
    if [[ ! $version_output =~ [0-9]+\.[0-9]+\.[0-9]+ ]]; then
        echo "Error: Cannot determine Python version"
        exit 1
    fi
    
    # Extract major.minor version
    local version=$(echo $version_output | grep -o '[0-9]\+\.[0-9]\+' | head -c 3)
    local major=$(echo $version | cut -d'.' -f1)
    local minor=$(echo $version | cut -d'.' -f2)
    
    if [[ $major -lt 3 ]] || ([[ $major -eq 3 ]] && [[ $minor -lt 10 ]]); then
        echo "Error: Python version must be 3.10 or higher (found $version)"
        exit 1
    fi
    
    echo "Python version $version is acceptable"
}

# Function to install Python dependencies
install_dependencies() {
    echo "Installing Python dependencies..."
    
    if [[ -f "requirements.txt" ]]; then
        # Check if packages are already installed
        local missing_packages=0
        
        while IFS= read -r requirement; do
            # Skip comments and empty lines
            [[ $requirement =~ ^# ]] && continue
            [[ -z $requirement ]] && continue
            
            # Extract package name (before ==, >=, <=, etc.)
            local pkg=$(echo $requirement | grep -o "^[a-zA-Z0-9_-]*")
            
            if ! python3 -c "import $(echo $pkg | tr a-z A-Z | tr '-' '_')" &> /dev/null; then
                echo "Need to install: $pkg"
                missing_packages=1
            fi
        done < requirements.txt
        
        if [[ $missing_packages -eq 1 ]]; then
            echo "Installing dependencies from requirements.txt..."
            pip3 install -r requirements.txt
        else
            echo "All dependencies already installed"
        fi
    else
        echo "Warning: requirements.txt not found in current directory"
    fi
}

# Function to copy and create Claude Code hook
install_claude_code() {
    echo "Installing Claude Code hook..."
    
    # Create Claude settings directory if it doesn't exist
    local claude_dir="$HOME/.claude"
    local settings_file="$claude_dir/settings.json"
    
    mkdir -p "$claude_dir"
    
    # Check if settings file exists, create basic structure if not
    if [[ ! -f "$settings_file" ]]; then
        echo '{"hooks": {}}' > "$settings_file"
        echo "Created basic $settings_file"
    fi
    
    # Copy Claude Code hook script to appropriate location within our own directory structure
    # Since we're installing locally, we'll put the hook in our current directory under a claude-hooks subfolder
    local claude_hook_dir="$HOME/.claude/hooks"
    mkdir -p "$claude_hook_dir"
    
    # Copy the hook script
    cp "./hooks/claude_code.py" "$claude_hook_dir/pii_shield_claude.py"
    chmod +x "$claude_hook_dir/pii_shield_claude.py"
    
    echo "Claude Code hook installed to $claude_hook_dir/pii_shield_claude.py"
    echo "Add the hook to your Claude Code by adding it to $settings_file"
    echo
    echo "Configuration snippet for Claude Code:"
    echo '
{
  "hooks": {
    "pii_shield": {
      "script": "'"$claude_hook_dir"'"/pii_shield_claude.py",
      "events": ["PreToolUse", "UserPromptSubmit"]
    }
  }
}'
    echo
}

# Function to copy and create Codex CLI hook
install_codex_cli() {
    echo "Installing Codex CLI hook..."
    
    # Create Codex hooks directory if it doesn't exist
    local codex_dir="$HOME/.codex"
    local hooks_file="$codex_dir/hooks.json"
    
    mkdir -p "$codex_dir"
    
    # Check if hooks file exists, create basic structure if not
    if [[ ! -f "$hooks_file" ]]; then
        echo '{"hooks": []}' > "$hooks_file"
        echo "Created basic $hooks_file"
    fi
    
    # Create Codex hooks directory and copy the script
    local codex_hook_dir="$HOME/.codex/plugins"
    mkdir -p "$codex_hook_dir"
    
    # Copy the hook script
    cp "./hooks/codex_cli.py" "$codex_hook_dir/pii_shield_codex.py"
    chmod +x "$codex_hook_dir/pii_shield_codex.py"
    
    echo "Codex CLI hook installed to $codex_hook_dir/pii_shield_codex.py"
    echo "Add the hook to your Codex CLI by updating $hooks_file"
    echo
    echo "Sample configuration snippet for Codex CLI:"
    echo '
{
  "hooks": [
    {
      "name": "pii_shield",
      "path": "'"$codex_hook_dir"'"/pii_shield_codex.py",
      "events": ["PreToolUse", "UserPromptSubmit"]
    }
  ]
}'
    echo
}

# Function to install OpenCode plugin
install_opencode() {
    echo "Installing OpenCode plugin..."
    
    # Create OpenCode plugins directory if it doesn't exist
    local opencode_dir="$HOME/.opencode/plugins"
    
    mkdir -p "$opencode_dir"
    
    # Compile the TypeScript plugin if we have tsc available, otherwise just copy
    if command -v tsc &> /dev/null; then
        echo "Compiling TypeScript plugin..."
        tsc "./hooks/opencode_hook.ts" --target es2020 --module commonjs --outfile "$opencode_dir/pii_shield_opencode.js"
    else
        # Copy and create a JavaScript adapter that will call our Python code
        echo "Creating JavaScript wrapper for OpenCode plugin..."
        cat > "$opencode_dir/pii_shield_opencode.js" << 'EOF'
// OpenCode Plugin: PII Shield
// Note: This is a JavaScript wrapper that calls the Python PII shield
const { spawnSync } = require('child_process');
const fs = require('fs');

const plugin = {
  name: 'PII-Shield',
  version: '1.0.0',
  hooks: {
    'tool.execute.before': async (context) => {
      // Extract the Python script path in the user's directory (assumes it's in the same dir as this plugin)
      const pythonScriptPath = __dirname + '/../../pii_shield.py';  // Adjust this path accordingly
      
      // Simple check - if Python code exists locally, we might call it; 
      // For this simplified version, we'll just check if the file is accessible
      if (fs.existsSync(pythonScriptPath)) {
        // This would typically call Python with the context data
        // Asynchronously run Python script to scan content
        try {
          // Prepare the tool and input data
          const toolName = context?.toolName || '';
          
          if (['read', 'bash', 'grep'].includes(toolName.toLowerCase())) {
            // Prepare input for PII scanning based on tool type
            let contentToScan = { tool: toolName };
            
            switch (toolName.toLowerCase()) {
              case 'read':
                contentToScan.filePath = context?.toolInput?.filePath || context?.input?.filePath;
                break;
              case 'bash':
                contentToScan.command = context?.toolInput?.command || context?.input?.command;
                break;
              case 'grep':
                contentToScan.pattern = context?.toolInput?.pattern || context?.input?.pattern;
                contentToScan.path = context?.toolInput?.path || context?.input?.path;
                break;
            }
            
            // Execute Python scanner with a timeout
            const result = spawnSync('python3', [pythonScriptPath, 'hook'], {
              input: JSON.stringify(contentToScan),
              maxBuffer: 10 * 1024 * 1024, // 10MB
              timeout: 5000, // 5 second timeout
            });
            
            // Check exit code
            if (result.status === 2) {
              // Python script exited with code 2 = PII detected
              const errorMessage = result.stderr ? result.stderr.toString().trim() : 'PII detected and blocked';
              throw new Error(`OpenCode PII Shield: ${errorMessage}`);
            } 
            // If we get here and exit code is not 2, continue normally
          }
        } catch (error) {
          // If there's an error in our checking logic, proceed with caution
          console.warn('PII Shield check failed:', error.message);
        }
      }
      
      return context;
    }
  }
};

module.exports = plugin;
EOF
    fi
    
    # Also copy the actual Python script to OpenCode's data directory for the plugin to use
    local opencode_scripts_dir="$HOME/.opencode/scripts"
    mkdir -p "$opencode_scripts_dir"
    cp "./pii_shield.py" "$opencode_scripts_dir/"
    cp "./hooks/opencode_hook.ts" "$opencode_dir/"  # Include TypeScript source as well
    chmod +x "$opencode_scripts_dir/pii_shield.py"
    
    echo "OpenCode plugin installed to $opencode_dir/pii_shield_opencode.js"
    echo "Python engine copied to $opencode_scripts_dir/pii_shield.py"
    echo
    echo "Note: Configure this plugin in your OpenCode environment according to its plugin system."
    echo
}

# Main install process
main() {
    # Verify we're in the right directory structure with expected files
    if [[ ! -f "pii_shield.py" || ! -d "hooks" ]]; then
        echo "Error: This script must be run from the root of the PII Shield project structure."
        echo "Expected to find pii_shield.py and hooks/ directory."
        exit 1
    fi
    
    if [[ $# -eq 0 ]]; then
        show_help
        exit 1
    fi
    
    # Check all parameters
    local claude=false
    local codex=false 
    local opencode=false
    
    for arg in "$@"; do
        case $arg in
            --claude-code)
                claude=true
                ;;
            --codex)
                codex=true
                ;;
            --opencode)
                opencode=true
                ;;
            --all)
                claude=true
                codex=true
                opencode=true
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $arg"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Check Python requirements
    check_python_version
    install_dependencies
    
    # Install selected hooks/plugins
    if [[ "$claude" == true ]]; then
        install_claude_code
    fi
    
    if [[ "$codex" == true ]]; then
        install_codex_cli
    fi
    
    if [[ "$opencode" == true ]]; then
        install_opencode
    fi
    
    echo "Installation complete!"
    echo
    echo "Remember to configure the hooks in your respective tools' configuration files:"
    echo "- Claude Code: Add the hook to ~/.claude/settings.json"
    echo "- Codex CLI: Add the hook to ~/.codex/hooks.json"
    echo "- OpenCode: Enable the plugin as per OpenCode's plugin system"
}

# Execute main function with all arguments
main "$@"