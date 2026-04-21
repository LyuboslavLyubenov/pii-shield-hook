#!/usr/bin/env python3
"""
Codex CLI Hook - PII/Secret Detection

This script integrates with the OpenAI Codex CLI's hook system to detect and block
PII and secrets before they are sent to the LLM. It follows Codex CLI's
hook protocol by reading JSON from stdin and outputting decisions as required.

The script handles two types of events:
- PreToolUse: For tools like Bash that might return sensitive data
- UserPromptSubmit: For user prompts that might contain sensitive information

If PII is detected, it outputs a block decision in Codex CLI's expected format
and can either output JSON or exit 2 with error on stderr. If clean, it exits 0.
"""

import json
import sys
import os
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
        # Invalid JSON input, allow the hook to proceed to avoid breaking Codex CLI
        sys.exit(0)
    except Exception:
        # Error reading stdin, allow the hook to proceed
        sys.exit(0)
    
    event_name = input_data.get("hookSpecificOutput", {}).get("hookEventName") or input_data.get("eventName")
    
    # Determine if this is a PreToolUse or UserPromptSubmit event
    if event_name == "PreToolUse":
        # Extract the necessary information based on tool type
        tool_use = input_data.get("call", input_data.get("tool_use", {}))
        tool_name = tool_use.get("name", tool_use.get("type", "")).lower()
        tool_input = tool_use.get("input", tool_use.get("tool_input", {}))
        
        # Extract text based on tool type
        text_to_scan = ""
        # For Codex CLI, mainly focus on bash commands which may contain sensitive data
        if tool_name in ["bash", "shell", "execute"]:
            text_to_scan = tool_input.get("command", "")
        
        if text_to_scan:
            # Scan the extracted text for PII
            findings = shield.scan(text_to_scan)
            
            # If any PII detected, block the execution
            if findings:
                # Extract unique entity types for the reason message
                unique_types = set(finding['type'] for finding in findings)
                
                # Output block decision in Codex format
                block_response = {
                    "decision": "block",
                    "reason": f"PII detected: {', '.join(sorted(unique_types))}. Redact before sending."
                }
                print(json.dumps(block_response))
                sys.exit(0)  # Codex expects exit 0 for block response
    
    elif event_name == "UserPromptSubmit":
        # Extract the user prompt
        prompt = input_data.get("prompt", "")
        
        # Some implementations might put the prompt in a different field
        if not prompt:
            prompt = input_data.get("text", "")
        
        if prompt:
            # Scan the prompt for PII
            findings = shield.scan(prompt)
            
            # If any PII detected, block the execution
            if findings:
                # Extract unique entity types for the reason message
                unique_types = set(finding['type'] for finding in findings)
                
                # Output block decision in Codex format
                block_response = {
                    "decision": "block", 
                    "reason": f"PII detected in prompt: {', '.join(sorted(unique_types))}. Redact before sending."
                }
                print(json.dumps(block_response))
                sys.exit(0)  # Codex expects exit 0 for block response
    
    elif event_name == "PreToolUseWithOutput":  # Additional case if Codex CLI has this event type
        # Handle cases where we're hooking tool use and output might contain PII
        tool_input = input_data.get("input", {})
        # This could be the output of a previous tool execution
        if "output" in tool_input:
            output_to_scan = tool_input["output"]
            findings = shield.scan(output_to_scan)
            
            if findings:
                # Extract unique entity types for the reason message
                unique_types = set(finding['type'] for finding in findings)
                
                # Alternatively, we can just write to stderr and exit with code 2
                error_msg = f"PII detected in tool output: {', '.join(sorted(unique_types))}"
                print(error_msg, file=sys.stderr)
                sys.exit(2)  # Exit code 2 means block execution with reason on stderr

    # If we reach here, either no recognized event or no PII detected
    # Exit cleanly (allowing the tool/command to proceed)
    # Implicitly exits with code 0, which means allow execution


if __name__ == "__main__":
    main()