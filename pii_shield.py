#!/usr/bin/env python3
"""
Core PII Shield engine for detecting and redacting PII/secret information.
"""

from transformers import pipeline
import torch
import re
from typing import List, Dict, Tuple


class PIIShield:
    def __init__(self, ner_model: str, threshold: float = 0.3):
        """
        Initialize the PII Shield with the specified NER model and confidence threshold.
        
        Args:
            ner_model: Name of the NER model to use
            threshold: Confidence threshold for NER detections
        """
        self.ner_model_name = ner_model
        self.threshold = threshold
        # Initialize NER pipeline using pre-trained model
        self.ner_pipeline = pipeline(
            "token-classification",
            model=self.ner_model_name,
            aggregation_strategy="simple",
            device=torch.device("cpu")
        )
        
    def scan(self, text: str) -> List[Dict]:
        """
        Scan text for PII and return list of findings.
        
        Implements a hybrid approach: runs regex scanning first, then NER scanning on 
        remaining parts not already detected by regex. Returns a merged list of findings 
        ordered appropriately so they can be applied sequentially during redaction 
        without position conflicts.
        
        Args:
            text: Text to scan for PII
             
        Returns:
            List of findings with keys: text, type, start, end, source
        """
        # Run regex scanning first (fast path)
        regex_results = self._regex_scan(text)
        
        # Run NER scanning to find remaining PII not caught by regex
        all_ner_results = self._ner_scan(text)
        
        # Avoid duplicate detections by filtering NER results that overlap with regex results
        unique_ner_results = []
        for ner_result in all_ner_results:
            overlap = False
            for regex_result in regex_results:
                # Check if intervals [start, end) overlap: start1 < end2 AND start2 < end1
                if (ner_result['start'] < regex_result['end'] and 
                    regex_result['start'] < ner_result['end']):
                    overlap = True
                    break
            
            if not overlap:
                unique_ner_results.append(ner_result)
        
        # Combine both lists
        all_results = regex_results + unique_ner_results
        
        # Ensure results are ordered in order of appearance in text (by start position)
        # This ensures they can be applied sequentially in redact without position conflicts
        all_results.sort(key=lambda x: x['start'])
        
        return all_results
        
    def redact(self, text: str) -> Tuple[str, Dict]:
        """
        Redact PII from text and return redacted version with mapping.
        
        Args:
            text: Text to redact
            
        Returns:
            tuple of (redacted_text, mapping_dict)
        """
        # Run regex scan first (faster, prioritized)
        regex_results = self._regex_scan(text)
        
        # Run NER scan second (avoiding duplicates with regex detections)
        ner_results = self._ner_scan(text)
        
        # Remove any NER results that would overlap with regex results
        # We prioritize regex over NER to prevent duplication and maintain consistency
        unique_results = []
        
        # Add all regex results first
        unique_results.extend(regex_results)
        
        # Add only NER results that don't overlap with regex results
        for ner_result in ner_results:
            overlap = False
            for regex_result in regex_results:
                # Check if intervals [start, end) overlap: start1 < end2 AND start2 < end1
                if (ner_result['start'] < regex_result['end'] and 
                    regex_result['start'] < ner_result['end']):
                    overlap = True
                    break
            
            if not overlap:
                unique_results.append(ner_result)
        
        # Sort results by start position in forward order to ensure proper counting
        # We'll still process from the end to beginning when doing replacement to preserve positions
        all_results = sorted(unique_results, key=lambda x: x['start'])
        
        redacted_text = text
        mapping = {}
        
        # Counters for each entity type for numbered placeholders
        type_counters = {}
        
        # Process each result in text order to ensure correct numbering (EMAIL_1, EMAIL_2, etc.)
        for result in all_results:
            entity_text = result['text']
            entity_type = result['type'].upper()  # Ensure type is uppercase
            
            # Increment counter for this entity type
            if entity_type not in type_counters:
                type_counters[entity_type] = 1
            else:
                type_counters[entity_type] += 1
            
            # Create placeholder like <EMAIL_1>, <NAME_2>, etc.
            placeholder = f'<{entity_type}_{type_counters[entity_type]}>'
            
            # Create mapping entry
            mapping[placeholder] = entity_text
            
            # Replace entity text with placeholder
            # We'll collect replacements and process from end to beginning to preserve positions
            result['computed_placeholder'] = placeholder
        
        # Now to properly replace while preserving positions, we collect the replacements
        # sorted by reverse start position
        sorted_for_replacement = sorted(all_results, key=lambda x: x['start'], reverse=True)
        
        current_text = text
        for result in sorted_for_replacement:
            start, end = result['start'], result['end']
            placeholder = result['computed_placeholder']
            # Replace entity text with placeholder
            current_text = (current_text[:start] + 
                           placeholder + 
                           current_text[end:])
        
        # Clean up temporary field before returning
        for result in all_results:
            if 'computed_placeholder' in result:
                del result['computed_placeholder']
        
        return current_text, mapping
        
    def _regex_scan(self, text: str) -> List[Dict]:
        """
        Run regex patterns on text to find structured secrets.
        
        Args:
            text: Text to scan for regex-based PII
             
        Returns:
            List of regex findings
        """
        findings = []
        
        # Process base patterns first - these find specific tokens and should take precedence
        # Pattern order matters for avoiding improper classification due to ordering
        patterns_by_priority = [
            # Highest priority patterns (least likely to cause false positives)
            ('OPENAI_API_KEY', r'\bsk-[a-zA-Z0-9]{20,}\b'),
            ('OPENAI_API_KEY', r'\bsk_live_[a-zA-Z0-9]{20,}\b'),
            ('GITHUB_TOKEN', r'\bghp_[a-zA-Z0-9]{36}\b'),
            ('GITHUB_TOKEN', r'\bgho_[a-zA-Z0-9]{36}\b'), 
            ('GITHUB_TOKEN', r'github_pat_[a-zA-Z0-9_]{22}_[a-zA-Z0-9_]{59}\b'),
            # Must match AWS access key BEFORE attempting to match anything in context patterns
            ('AWS_ACCESS_KEY', r'\bAKIA[A-Z0-9]{16}\b'), 
            ('JWT_TOKEN', r'\beyJ[A-Za-z0-9._-]+\b'),  # JWT starts with eyJ
            
            # Personal info
            ('SSN', r'\b\d{3}-\d{2}-\d{4}\b'),
            ('CREDIT_CARD', r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{14}|(?:\d{4}[-\s]?){3}\d{4}|(?:\d{4}[-\s]?){2}\d{7})\b'),
            ('EMAIL', r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            ('PHONE', r'\b(?:\+?1[-.\s]?)?(?:\([0-9]{3}\)|[0-9]{3})[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'),
        ]
        
        for entity_type, pattern in patterns_by_priority:
            for match in re.finditer(pattern, text):
                if (entity_type == 'AWS_ACCESS_KEY'):
                    # Additional check to make sure it's a valid AKIA format
                    matched = match.group(0)
                    if matched.startswith('AKIA') and len(matched) == 20 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' for c in matched[4:]):
                        findings.append({
                            'text': matched,
                            'type': entity_type,
                            'start': match.start(),
                            'end': match.end(),
                            'source': 'regex'
                        })
                else:
                    findings.append({
                        'text': match.group(0),
                        'type': entity_type,
                        'start': match.start(),
                        'end': match.end(),
                        'source': 'regex'
                    })
        
        # Separate handling for patterns that extract secrets from context
        # These should go AFTER base patterns to avoid interfering with specific ones
        secret_patterns = [
            ('AWS_SECRET_KEY', r'(?i)(?:aws_?access_?key_?id|aws_?secret_?access_?key|aws_?session_?token|secret).*?[=:]\s*[\'"]?([A-Za-z0-9/+]{40})(?:[\'"]|\s|$)'),
            ('GENERATOR_API_KEY', r'(?i)(?:api_?key|api|token|secret_key|bearer_token).*?[=:]\s*[\'"]?([A-Za-z0-9_-]{20,40})(?:[\'"]|\s|,|$)'),
        ]
        
        context_secrets = []
        for entity_type, pattern in secret_patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                if match.groups():
                    secret_value = match.group(1)
                    # Use the capture group's actual position
                    context_secrets.append({
                        'text': secret_value,
                        'type': entity_type,
                        'start': match.start(1),  # Start of capture group 1
                        'end': match.end(1),      # End of capture group 1
                        'source': 'regex'
                    })
        
        # Special cases for different assignment syntaxes: handle patterns like 'password=password_value', 'password:password_value'  
        # Two separate patterns to handle = vs :
        password_pattern_equals = r'(?i)\b(password|passwd|pass|pwd|pwd_?key|secret|token|db_pass)\s*[=]\s*[\'"]?([^\s;,\'"]+)\b'
        password_pattern_colons = r'(?i)\b(password|passwd|pass|pwd|pwd_?key|secret|token|db_pass)\s*[:]\s*[\'"]?([^\s;,\'"]+)\b'
        
        for match in re.finditer(password_pattern_equals, text, re.IGNORECASE):
            word = match.group(1)  # The variable name like 'password'
            value = match.group(2)  # The actual value like "mypass123"
            
            context_secrets.append({
                'text': value,
                'type': 'PASSWORD_CONFIG',
                'start': match.start(2), # Use position of captured value (group 2)
                'end': match.end(2),     # End of captured value (group 2)
                'source': 'regex'
            })
          
        for match in re.finditer(password_pattern_colons, text, re.IGNORECASE):
            word = match.group(1)  # The variable name like 'password'
            value = match.group(2) # The actual value like "mypass123"
            
            context_secrets.append({
                'text': value,
                'type': 'PASSWORD_CONFIG',
                'start': match.start(2), # Use position of captured value (group 2)
                'end': match.end(2),     # End of captured value (group 2)
                'source': 'regex'
            })
        
        # Combine findings from base patterns with those from context patterns
        all_findings = findings + context_secrets
        
        # Define priorities for deduplication (higher number = higher priority)
        priority_map = {
            'JWT_TOKEN': 99, 'GITHUB_TOKEN': 98, 'OPENAI_API_KEY': 97, 'AWS_ACCESS_KEY': 96,  # API keys
            'AWS_SECRET_KEY': 95, 'GENERATOR_API_KEY': 94, 'PASSWORD_CONFIG': 93,               # Secrets/values
            'SSN': 90, 'CREDIT_CARD': 89, 'EMAIL': 80,                                         # Personal info
            'PHONE': 50  # Lower priority (as they can be substrings of larger tokens)
        }
        
        # Sort findings to help with deduplication
        # Order by: start pos, descending length (to prefer longer matches in case of overlap), then priority
        all_findings.sort(key=lambda x: (x['start'], -(x['end'] - x['start']), priority_map.get(x['type'], 0)))
        
        # Deduplicate overlapping findings - keep the one with higher priority
        deduplicated = []
        for finding in all_findings:
            overlapped = False
            for i, existing in enumerate(deduplicated):
                # Check for overlap: intervals [start, end) overlap if start1 < end2 AND start2 < end1
                if finding['start'] < existing['end'] and existing['start'] < finding['end']:
                    # Overlap detected - keep the one with higher priority based on our priority map
                    current_priority = priority_map.get(finding['type'], 0)
                    existing_priority = priority_map.get(existing['type'], 0)
                    
                    if current_priority > existing_priority:
                        # Current has higher priority, replace the existing one                        
                        deduplicated[i] = finding
                    elif current_priority == existing_priority and (finding['end'] - finding['start']) > (existing['end'] - existing['start']):
                        # Same priority but longer match wins
                        deduplicated[i] = finding
                    # Otherwise, keep existing and skip new finding
                    
                    overlapped = True
                    break
            
            if not overlapped:
                deduplicated.append(finding)
        
        # Final sort by start position
        deduplicated.sort(key=lambda x: x['start'])
        return deduplicated
        
    def _ner_scan(self, text: str) -> List[Dict]:
        """
        Run NER model on text to find unstructured PII.
        
        Args:
            text: Text to scan for NER-based PII
             
        Returns:
            List of NER findings
        """
        results = []
        try:
            ner_results = self.ner_pipeline(text)
            
            for entity in ner_results:
                # Only include results that meet the confidence threshold
                if entity['score'] >= self.threshold:
                    entity_type = entity['entity_group']
                    entity_text = entity['word']
                    
                    # Skip common programming terms that commonly cause false positives
                    lower_entity_text = entity_text.lower()
                    false_positive_keywords = {
                        # Programming concepts
                        'authentication', 'authorization', 'admin', 'client', 'server',
                        'database', 'connection', 'session', 'cookie', 'cache', 'module',
                        'function', 'method', 'class', 'interface', 'service', 'api',
                        'endpoint', 'request', 'response', 'parameter', 'variable',
                        'configuration', 'settings', 'environment', 'production',
                        'development', 'testing', 'integration', 'deployment',
                        # Common tech words
                        'login', 'logout', 'register', 'setup', 'initialize', 'build',
                        'compile', 'deploy', 'test', 'debug', 'release', 'version',
                        'package', 'library', 'framework', 'application', 'software'
                    }
                    
                    # Map some common NER labels to more specific types if needed
                    entity_type = entity_type.upper()
                    
                    # Skip if this is a likely false positive
                    if lower_entity_text in false_positive_keywords:
                        continue
                    
                    results.append({
                        'text': entity_text,
                        'type': entity_type,
                        'start': entity['start'],
                        'end': entity['end'],
                        'source': 'ner'
                    })
        except Exception:
            # If NER fails for any reason, return empty list rather than failing completely
            pass
            
        return results


def main():
    """Main entry point for hook protocol"""
    import sys
    import json
    
    # Check arguments to determine mode - extended to support CLI hook mode
    if len(sys.argv) >= 3 and sys.argv[1] == "--hook-mode" and sys.argv[2] == "stdin":
        # Read input from stdin (as per hook protocol)
        try:
            input_data = json.loads(sys.stdin.read())
            
            # Initialize PIIShield with the appropriate model
            # Using a default NER model as specified in requirements
            shield = PIIShield("Isotonic/deberta-v3-base_finetuned_ai4privacy_v2")
            
            # Extract hook event information to determine what to process
            hook_event_name = input_data.get('hook_event_name', input_data.get('event', '')).lower() 
            
            # Process based on the event type
            if hook_event_name == 'pretooluse':
                # Handle PreToolUse events
                tool_input = input_data.get('tool_input', {})
                tool_type = input_data.get('tool', '').lower()
                
                # Determine what to scan based on tool type
                text_to_scan = ""
                if tool_type in ('bash', 'execute_command', 'cmd'):
                    # For bash commands, extract the command string for scanning
                    text_to_scan = tool_input.get('command', tool_input.get('command_string', ''))
                elif tool_type in ('read', 'file_read'):
                    # For read commands, get the file path to scan
                    text_to_scan = tool_input.get('filePath', tool_input.get('file_path', '')).lower()
                elif tool_type in ('grep', 'find_in_files'):
                    # For grep/find commands, get the search term/pattern
                    text_to_scan = tool_input.get('pattern', tool_input.get('query', tool_input.get('search_term', '')))
                    if 'path' in tool_input:
                        text_to_scan += " " + tool_input['path']
                    elif 'file_path' in tool_input:
                        text_to_scan += " " + tool_input['file_path']
                elif 'command' in tool_input:
                    # Generic fallback for commands
                    text_to_scan = tool_input['command']
                elif 'text' in tool_input or 'content' in tool_input or 'prompt' in tool_input:
                    # Look for other text content
                    for field in ['text', 'content', 'prompt']:
                        if field in tool_input:
                            text_to_scan = tool_input[field]
                            break
                
                # Perform redaction on the extracted text
                if text_to_scan:
                    redacted_text, mapping = shield.redact(str(text_to_scan))
                    
                    if mapping:  # If any redaction occurred, it indicates PII/secret detection
                        sensitive_types = list(set(k.split('_')[0].strip('<>') for k in mapping.keys()))
                        # Output detection result
                        result = {
                            "hookSpecificOutput": {
                                "hookEventName": hook_event_name,
                                "permissionDecision": "deny", 
                                "permissionDecisionReason": f"PII detected: {', '.join(sensitive_types)}. Redact before sending."
                            }
                        }
                        print(json.dumps(result))
                        sys.exit(0)  # Exit code 0 as allowed decision is returned in JSON
                    else:
                        # No sensitive data found - proceed normally
                        result = {}
                        print(json.dumps(result))  # Empty JSON object means no issue
                        sys.exit(0)
                else:
                    # No meaningful content to scan found
                    result = {}
                    print(json.dumps(result))
                    sys.exit(0)
                
            elif hook_event_name == 'userpromptsubmit':
                # Handle UserPromptSubmit events
                prompt = input_data.get('prompt', '')
                
                # Perform redaction on the prompt
                if prompt:
                    redacted_prompt, mapping = shield.redact(str(prompt))
                    
                    if mapping:  # If any redaction occurred, it indicates PII/secret detection
                        sensitive_types = list(set(k.split('_')[0].strip('<>') for k in mapping.keys()))
                        # Output detection result as deny decision
                        result = {
                            "hookSpecificOutput": {
                                "hookEventName": hook_event_name,
                                "permissionDecision": "deny",
                                "permissionDecisionReason": f"PII detected in prompt: {', '.join(sensitive_types)}. Redact before sending."
                            }
                        }
                        print(json.dumps(result))
                        sys.exit(0)  # Exit code 0 as allowed decision is returned in JSON
                    else:
                        # No sensitive data found - proceed normally
                        result = {}
                        print(json.dumps(result))  # Empty JSON object means no issue
                        sys.exit(0)
                else:
                    # No meaningful prompt to scan found
                    result = {}
                    print(json.dumps(result))
                    sys.exit(0)
            
            elif hook_event_name in ['posttoolresult', 'toolresultreceived']:
                # For PostToolResult events, scan the tool's result/output
                result_data = input_data.get('result', {})
                tool_output = None
                
                # Try different common fields where tool output might be stored
                for field in ['output', 'stdout', 'stderr', 'response', 'content', 'text', 'result']:
                    if field in result_data:
                        tool_output = result_data[field]
                        break
                        
                # If nothing is found under result object try direct lookup in input_data
                if tool_output is None:
                    for field in ['output', 'result_text', 'content']:
                        if field in input_data:
                            tool_output = input_data[field]
                            break
                
                if tool_output is not None:
                    # Perform redaction on the tool output
                    text_to_scan = str(tool_output) if not isinstance(tool_output, str) else tool_output
                    redacted_output, mapping = shield.redact(text_to_scan)
                    
                    if mapping:
                        # Return the redacted result along with mapping to restore values back if needed
                        sensitive_types = list(set(k.split('_')[0].strip('<>') for k in mapping.keys()))
                        result = {
                            "replacementResult": redacted_output,
                            "detectedEntities": list(mapping.values()),
                            "redactionInfo": {
                                "entitiesDetected": True,
                                "typeCount": len(set(k.split('_')[0].strip('<>') for k in mapping.keys())),
                                "totalRedactions": len(mapping.keys()),
                                "entityTypes": sensitive_types
                            }
                        }
                        print(json.dumps(result))
                        sys.exit(0)
                    else:
                        # No sensitive data found - return original result unchanged
                        result = {
                            "replacementResult": tool_output,
                            "redactionInfo": {
                                "entitiesDetected": False,
                                "totalRedactions": 0
                            }
                        }
                        print(json.dumps(result))
                        sys.exit(0)
                else:
                    # Nothing to.scan in the tool result
                    result = {}
                    print(json.dumps(result))
                    sys.exit(0)
                    
            else:
                # Unknown event type - pass through
                result = {}
                print(json.dumps(result))
                sys.exit(0)
                
        except json.JSONDecodeError as e:
            # Invalid JSON input
            print(f"Hook protocol error: Invalid JSON input - {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            # Other errors
            print(f"Hook protocol error: {e}", file=sys.stderr)
            sys.exit(1)
          
    # Legacy hook logic (for backward compatibility)
    elif len(sys.argv) >= 2 and sys.argv[1] == "hook":
        # Read input from stdin (as per hook protocol)
        try:
            input_data = json.loads(sys.stdin.read())
            
            # Initialize PIIShield with the appropriate model
            # Using a default NER model as specified in requirements
            shield = PIIShield("Isotonic/deberta-v3-base_finetuned_ai4privacy_v2")
            
            # Extract tool information to determine what to scan and how to handle it
            tool_name = input_data.get('tool', '').lower() if isinstance(input_data, dict) else ''
            
            # Process based on the type of tool
            if tool_name == 'bash':
                # For bash commands, scan the command string for secrets
                command = input_data.get('command', '')
                redacted_cmd, mapping = shield.redact(str(command))
                
                if mapping:  # If any redaction occurred, it indicates PII/secret detection
                    sensitive_types = list(set(k.split('_')[0].strip('<>') for k in mapping.keys()))
                    error_msg = f'PII/Secrets detected in bash command: {", ".join(sensitive_types)}. Blocked for security.'
                    print(error_msg, file=sys.stderr)
                    sys.exit(2)  # Exit code 2 indicates block
                    
                # Command is clean, allow execution
                result = {
                    'status': 'allowed',
                    'original_command': command,
                    'redaction_needed': False
                }
                print(json.dumps(result))
                
            elif tool_name == 'grep':
                # For grep commands, scan both the pattern and path for sensitive info
                pattern = input_data.get('pattern', '')
                path = input_data.get('path', '')
                
                search_target = f"{pattern} {path}".strip()
                redacted_target, mapping = shield.redact(search_target)
                
                if mapping:  # If any redaction occurred, it indicates PII/secret detection
                    sensitive_types = list(set(k.split('_')[0].strip('<>') for k in mapping.keys()))
                    error_msg = f'PII/Secrets detected in grep search: {", ".join(sensitive_types)}. Blocked for security.'
                    print(error_msg, file=sys.stderr)
                    sys.exit(2)  # Exit code 2 indicates block
                    
                # Search terms are clean, allow execution
                result = {
                    'status': 'allowed',
                    'original_pattern': pattern,
                    'original_path': path,
                    'redaction_needed': False
                }
                print(json.dumps(result))
                
            elif tool_name == 'read':
                # For read commands, scan the file path for PII info in the path itself
                file_path = input_data.get('filePath', '') or input_data.get('path', '')
                
                # Note: Actually reading the file could be sensitive as well, but we'd likely scan
                # file contents in a 'tool.execute.after' hook which is beyond scope here
                redacted_path, mapping = shield.redact(file_path)
                
                if mapping:  # If any redaction occurred in file path, flag as issue
                    sensitive_types = list(set(k.split('_')[0].strip('<>') for k in mapping.keys()))
                    error_msg = f'Sensitive identifiers detected in file path: {", ".join(sensitive_types)}. Blocked for security.'
                    print(error_msg, file=sys.stderr)
                    sys.exit(2)  # Exit code 2 indicates block
                    
                # File path is clean, allow execution
                result = {
                    'status': 'allowed',
                    'file_path': file_path,
                    'redaction_needed': False
                }
                print(json.dumps(result))
                
            elif isinstance(input_data, str):
                # If input is just a string, scan it directly
                redacted_text, mapping = shield.redact(input_data)
                
                if mapping:
                    sensitive_types = list(set(k.split('_')[0].strip('<>') for k in mapping.keys()))
                    error_msg = f'PII/Secrets detected: {", ".join(sensitive_types)}. Blocked for security.'
                    print(error_msg, file=sys.stderr)
                    sys.exit(2)
                    
                result = {'status': 'allowed', 'original': input_data, 'redacted': redacted_text}
                print(json.dumps(result))
            else:
                # For other cases, process the overall content
                # Find string data somewhere in the input that might contain sensitive info
                search_fields = ['text', 'content', 'command', 'data']
                scan_text = ""
                
                for field in search_fields:
                    if field in input_data:
                        scan_text += str(input_data[field]) + " "
                
                if not scan_text:
                    # If no specific fields, attempt to create a string representation of the whole input
                    scan_text = json.dumps(input_data) if isinstance(input_data, dict) else str(input_data)
                
                redacted_text, mapping = shield.redact(scan_text)
                
                if mapping:
                    sensitive_types = list(set(k.split('_')[0].strip('<>') for k in mapping.keys()))
                    error_msg = f'PII/Secrets detected: {", ".join(sensitive_types)}. Blocked for security.'
                    print(error_msg, file=sys.stderr)
                    sys.exit(2)
                    
                result = {
                    'status': 'allowed', 
                    'original_data': input_data,
                    'redacted_content': redacted_text
                }
                print(json.dumps(result))
                
        except json.JSONDecodeError as e:
            # Invalid JSON input
            print(f"Hook protocol error: Invalid JSON input - {e}", file=sys.stderr)
            sys.exit(1)
        except FileNotFoundError as e:
            # File not found for read operations
            print(f"Hook protocol error: File not found - {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            # Other errors
            print(f"Hook protocol error: {e}", file=sys.stderr)
            sys.exit(1)
        
    else:
        # Without hook argument, this could be used for testing directly
        import sys
        print("PIIShield ready for hook operations. Usage: python3 pii_shield.py --hook-mode stdin")
        sys.exit(0)

if __name__ == "__main__":
    main()
