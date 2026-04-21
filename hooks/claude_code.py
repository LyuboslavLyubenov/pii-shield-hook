#!/usr/bin/env python3
"""
Claude Code Hook - PII/Secret Detection

This script integrates with Claude Code's hook system to detect and block
PII and secrets before they are sent to the LLM. It follows Claude Code's
hook protocol by reading JSON from stdin and outputting decisions as required.

The script handles two types of events:
- PreToolUse: For tools like Read, Bash, Grep, Glob that might return sensitive data
- UserPromptSubmit: For user prompts that might contain sensitive information

If PII is detected, it outputs a denial decision in Claude Code's expected format
and exits with code 0. If clean, it outputs nothing and exits with code 0.
"""

import json
import sys
import os

# Add the parent directory to the Python path so we can import pii_shield
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

from pii_shield import PIIShield

def main():
    # Initialize the PII shield with the NER model
    # Use the model specified in the goals document
    ner_model = "Isotonic/deberta-v3-base_finetuned_ai4privacy_v2"
    try:
        shield = PIIShield(ner_model=ner_model, threshold=0.3)
    except Exception as e:
        # If the model is not available or fails to load, we print an error but exit 0 to allow the hook to proceed
        # This is a safety measure to not block users if there are issues with detection
        print(f"Warning: Could not initialize PII Shield - {str(e)}", file=sys.stderr)
        sys.exit(0)
    
    # Read JSON input from stdin
    try:
        input_data = json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        # Invalid JSON input, allow the hook to proceed to avoid breaking Claude Code
        sys.exit(0)
    except Exception:
        # Error reading stdin, allow the hook to proceed
        sys.exit(0)
    
    event_name = (
        input_data.get("hookSpecificOutput", {}).get("hookEventName") or 
        input_data.get("hook_event_name") or 
        input_data.get("eventName") or
        input_data.get("event_name") or
        input_data.get("event", "").split(".")[-1]  # Extract event name from something like "tool.use.pre"
    )
    
    # Determine if this is a PreToolUse or UserPromptSubmit event
    if event_name == "PreToolUse":
        # Extract the necessary information based on tool type - support multiple input formats
        # Format 1: Direct tool information on input ({"tool_name": "...", "tool_input": {...}})
        direct_tool_name = input_data.get("tool_name", "").lower() 
        direct_tool_input = input_data.get("tool_input", {})
        
        # Format 2: Nested in call or tool_use objects
        tool_use = input_data.get("call", input_data.get("tool_use", {}))
        call_tool_name = tool_use.get("name", tool_use.get("type", "")).lower()
        call_tool_input = tool_use.get("input", tool_use.get("tool_input", {}))
        
        # Prefer the direct format if available, fallback to call/tool_use structures
        tool_name = direct_tool_name or call_tool_name
        tool_input = direct_tool_input or call_tool_input
        
        # Extract text based on tool type
        text_to_scan = ""
        if tool_name == "read" or tool_name == "file":
            text_to_scan = tool_input.get("filePath", "")
        elif tool_name in ["bash", "shell", "execute"]:
            text_to_scan = tool_input.get("command", "")
        elif tool_name in ["grep", "find"]:
            # This may be the search pattern or file contents, depending on the context
            text_to_scan = tool_input.get("pattern", "") or tool_input.get("filePath", "")
        elif tool_name == "glob":
            text_to_scan = tool_input.get("pattern", "")
        
        if text_to_scan:
            # Scan the extracted text for PII
            findings = shield.scan(text_to_scan)
            
            # If any PII detected, output denial decision
            if findings:
                # Extract unique entity types for the reason message
                unique_types = set(finding['type'] for finding in findings)
                
                deny_response = {
                    "hookSpecificOutput": {
                        "hookEventName": event_name,
                        "permissionDecision": "deny",
                        "permissionDecisionReason": f"PII detected: {', '.join(sorted(unique_types))}. Redact before sending."
                    }
                }
                print(json.dumps(deny_response))
                sys.exit(0)  # Exit 0 as per protocol, denial is indicated in the JSON output
    
    elif event_name == "UserPromptSubmit":
        # Extract the user prompt
        prompt = input_data.get("prompt", "")
        
        # Some implementations might put the prompt in a different field
        if not prompt:
            prompt = input_data.get("text", "")
        
        if prompt:
            # Scan the prompt for PII
            findings = shield.scan(prompt)
            
            # If any PII detected, output denial decision
            if findings:
                # Extract unique entity types for the reason message
                unique_types = set(finding['type'] for finding in findings)
                
                deny_response = {
                    "hookSpecificOutput": {
                        "hookEventName": event_name,
                        "permissionDecision": "deny",
                        "permissionDecisionReason": f"PII detected in prompt: {', '.join(sorted(unique_types))}. Redact before sending."
                    }
                }
                print(json.dumps(deny_response))
                sys.exit(0)  # Exit 0 as per protocol
    
    # If we reach here, either no recognized event or no PII detected
    # Exit cleanly with no output (exit 0 is implicit)


if __name__ == "__main__":
    main()