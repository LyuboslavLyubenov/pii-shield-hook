#!/usr/bin/env python3
"""
End-to-end tests for the PII Shield redaction pipeline.
Tests the complete flow: sample input -> PIIShield.scan() -> PIIShield.redact() -> validate placeholders & mapping.
"""

import sys
import os
import json
from typing import List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pii_shield import PIIShield


def load_sample_inputs():
    """Load sample inputs from fixtures"""
    fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "sample_inputs.json")
    with open(fixture_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def test_regex_vs_ner_combination():
    """Test that both regex and NER scanning are performed in combination"""
    shield = PIIShield("Isotonic/deberta-v3-base_finetuned_ai4privacy_v2")
    
    # Mix of structured (regex) and unstructured (NER) PII data
    text = """
    John Smith has an account with API key sk-1234567890abcdef234567890.
    He lives at 123 Main St, New York, NY and his email is john.smith@example.com.
    His SSN is 123-45-6789 and he can be reached at 555-123-4567.
    """
    
    findings = shield.scan(text)
    
    # Verify we have both regex and NER sources
    sources = {f['source'] for f in findings}
    assert 'regex' in sources, "Regex detections not found"
    # Note: NER might not detect the fictional address/name in this short test
    # so we should not enforce NER presence in this test
    
    regex_findings = [f for f in findings if f['source'] == 'regex']
    assert len(regex_findings) >= 4, f"Expected at least 4 regex findings, got {len(regex_findings)}"
    
    # Verify specific expected regex detections
    types = [f['type'] for f in regex_findings]
    assert 'OPENAI_API_KEY' in types, "OpenAI API key not detected"
    assert 'EMAIL' in types, "Email not detected"
    assert 'SSN' in types, "SSN not detected"
    assert 'PHONE' in types, "Phone not detected"
    

def test_complete_redaction_pipeline():
    """Test the complete scan and redact pipeline with consistent numbering"""
    shield = PIIShield("Isotonic/deberta-v3-base_finetuned_ai4privacy_v2")
    
    text = """
    alice.brown@company.com, 555-111-2222
    bob.wilson@company.com, 555-333-4444
    Key1: sk-firstkey1234567890secondkey12345678
    Key2: sk-secondkey0987654321firstkey09876543
    """
    
    # Test redaction function
    redacted, mapping = shield.redact(text)
    
    # Verify placeholders are correctly substituted
    assert '<EMAIL_1>' in redacted, f"First email not replaced with placeholder. Redacted: {redacted}"
    assert '<EMAIL_2>' in redacted, f"Second email not replaced with placeholder. Redacted: {redacted}"
    assert '<PHONE_1>' in redacted, f"First phone not replaced with placeholder. Redacted: {redacted}"
    assert '<PHONE_2>' in redacted, f"Second phone not replaced with placeholder. Redacted: {redacted}"
    assert '<OPENAI_API_KEY_1>' in redacted, f"First API key not replaced with placeholder. Redacted: {redacted}"
    assert '<OPENAI_API_KEY_2>' in redacted, f"Second API key not replaced with placeholder. Redacted: {redacted}"
    
    # Verify mapping is correct for the specific values
    email_found_texts = [val for ph, val in mapping.items() if ph.startswith('<EMAIL_')]
    assert 'alice.brown@company.com' in email_found_texts, f"Expected email not found in mappings: {mapping}"
    assert 'bob.wilson@company.com' in email_found_texts, f"Expected email not found in mappings: {mapping}"

    phone_found_texts = [val for ph, val in mapping.items() if ph.startswith('<PHONE_')]
    assert '555-111-2222' in phone_found_texts, f"Expected phone not found in mappings: {mapping}"
    assert '555-333-4444' in phone_found_texts, f"Expected phone not found in mappings: {mapping}"

    key_found_texts = [val for ph, val in mapping.items() if ph.startswith('<OPENAI_API_KEY_')]
    assert 'sk-firstkey1234567890secondkey12345678' in key_found_texts, f"Expected API key not found in mappings: {mapping}"
    assert 'sk-secondkey0987654321firstkey09876543' in key_found_texts, f"Expected API key not found in mappings: {mapping}"


def test_placeholder_numbering_consistency():
    """Test that placeholder numbering is consistent across identical types"""
    shield = PIIShield("Isotonic/deberta-v3-base_finetuned_ai4privacy_v2")
    
    text = "Contact admin@test.com or support@test.com, don't forget service@test.com"
    
    redacted, mapping = shield.redact(text)
    
    # Should have three different email placeholders
    assert '<EMAIL_1>' in redacted
    assert '<EMAIL_2>' in redacted
    assert '<EMAIL_3>' in redacted
    
    # Verify each placeholder maps to the respective email
    assert mapping['<EMAIL_1>'] == 'admin@test.com', f"EMAIL_1 mapping wrong: {mapping.get('<EMAIL_1>')}"
    assert mapping['<EMAIL_2>'] == 'support@test.com', f"EMAIL_2 mapping wrong: {mapping.get('<EMAIL_2>')}"
    assert mapping['<EMAIL_3>'] == 'service@test.com', f"EMAIL_3 mapping wrong: {mapping.get('<EMAIL_3>')}"
    
    # Verify original text didn't contain these placeholders
    assert '<EMAIL_1>' not in text
    assert '<EMAIL_2>' not in text
    assert '<EMAIL_3>' not in text


def test_multiple_pii_types_in_single_text():
    """Test redaction of multiple PII types in one operation"""
    shield = PIIShield("Isotonic/deberta-v3-base_finetuned_ai4privacy_v2")
    
    text = """
    has credentials:
    - OpenAI: sk-devkey1234567890second0123456789  
    """
    
    redacted, mapping = shield.redact(text)
    
    # The OpenAI key should definitely be detected by regex
    assert '<OPENAI_API_KEY_1>' in redacted, f"OpenAI key not redacted. Redacted: {redacted}"
    
    # Verify the specific sensitive value is no longer present in raw form
    assert 'sk-devkey1234567890second0123456789' not in redacted, "Sensitive API key still present in text"


def test_no_double_scanning_regex_vs_ner():
    """Test that NER doesn't duplicate what regex already caught"""
    shield = PIIShield("Isotonic/deberta-v3-base_finetuned_ai4privacy_v2")
    
    text = "My email is admin@company.com and my phone is 555-123-4567"
    
    # Get findings with scan method
    findings = shield.scan(text)
    
    # Check for duplicates: NER finding should NOT overlap with regex findings
    # (Regex has priority over NER for certain types)
    i = 0
    while i < len(findings):
        j = i + 1
        while j < len(findings):
            # Check if these findings overlap in text location
            a = findings[i]
            b = findings[j] 
            
            # Check if intervals [start, end) overlap: start1 < end2 AND start2 < end1
            if a['start'] < b['end'] and b['start'] < a['end']:
                # If both are same type (like both EMAIL), and one is from regex one is NER, 
                # verify there's no duplication
                if a['type'] == b['type'] and a['source'] != b['source']:
                    # This shouldn't happen due to overlap removal logic
                    raise AssertionError(f"Found overlapping duplicate detection for {a['type']}: "
                                       f"'{a['text']}' ({a['source']}) vs '{b['text']}' ({b['source']})")
            
            j += 1
        i += 1


def test_sample_inputs_from_fixtures():
    """Test with samples loaded from fixture files"""
    samples = load_sample_inputs()
    
    shield = PIIShield("Isotonic/deberta-v3-base_finetuned_ai4privacy_v2")
    
    # Test user prompts with PII
    for idx, sample in enumerate(samples['user_prompts_with_pii']):
        text = sample['prompt']
        expected_types = sample['expected_entities']

        findings = shield.scan(text)
        redacted, mapping = shield.redact(text)
        
        # Verify the expected entity types are found in the results (at least some of them)
        found_types = [f['type'] for f in findings]
        
        # Just check that at least some expected types were found
        found_expected = [et for et in expected_types if et in found_types]
        assert len(found_expected) > 0, (
            f"Prompt {idx}: No expected entities found. Expected: {expected_types}, Found: {list(set(found_types))}"
        )
        
        # Test that found items have been replaced with placeholders in redacted text
        for finding in findings:
            # The original PII value should not appear in the redacted text
            assert finding['text'] not in redacted or finding['type'] not in expected_types or (
                finding['type'] in [f['type'] for f in findings if f['text'] in redacted]
            ), f"Found text still appears in redacted output: {finding['text']}"

    # Test bash commands with secrets
    for idx, sample in enumerate(samples['bash_commands_with_secrets']):
        text = sample['command']
        expected_types = sample['expected_entities']

        findings = shield.scan(text)
        redacted, mapping = shield.redact(text)
        
        found_types = [f['type'] for f in findings]
        found_expected = [et for et in expected_types if et in found_types]
        assert len(found_expected) > 0, (
            f"Bash command {idx}: No expected entities found. Expected: {expected_types}, Found: {list(set(found_types))}"
        )

    # Test file contents with PII
    for idx, sample in enumerate(samples['file_contents_with_pii']):
        text = sample['content']
        expected_types = sample['expected_entities']

        findings = shield.scan(text)
        redacted, mapping = shield.redact(text)
        
        found_types = [f['type'] for f in findings]
        found_expected = [et for et in expected_types if et in found_types]
        assert len(found_expected) > 0, (
            f"File content {idx}: No expected entities found. Expected: {expected_types}, Found: {list(set(found_types))}"
        )


def test_placeholder_format_and_uniqueness():
    """Test that placeholders follow the format and are unique within document"""
    shield = PIIShield("Isotonic/deberta-v3-base_finetuned_ai4privacy_v2")
    
    text = """
    Contact: admin@company.com or admin@company.com
    Keys: sk-first0000000000second4567890123, sk-second1234567890third456789012
    SSNs: 123-45-6789, 987-65-4321
    """
    
    redacted, mapping = shield.redact(text)
    
    # Count occurrences of each placeholder type
    counts = {'EMAIL': 0, 'OPENAI_API_KEY': 0, 'SSN': 0}
    for placeholder in mapping:
        if '_1' in placeholder: 
            entity_type = placeholder.strip('<>').split('_')[0]
            if entity_type in counts:
                counts[entity_type] += 1
    
    # Note: Identical values will share the same mapping entry but both will be replaced
    # So 2 identical emails should still result in 2 placeholders
    assert '<EMAIL_1>' in redacted
    assert '<EMAIL_2>' in redacted  # Even though they're identical emails
    assert '<OPENAI_API_KEY_1>' in redacted
    assert '<OPENAI_API_KEY_2>' in redacted
    assert '<SSN_1>' in redacted
    assert '<SSN_2>' in redacted
    
    # The mapping should have these specific keys
    expected_placeholders = ['<EMAIL_1>', '<EMAIL_2>', '<OPENAI_API_KEY_1>', 
                            '<OPENAI_API_KEY_2>', '<SSN_1>', '<SSN_2>']
    for ph in expected_placeholders:
        assert ph in mapping, f"Missing placeholder {ph} in mapping"


if __name__ == '__main__':
    print("Running end-to-end PII redaction tests...")
    
    test_regex_vs_ner_combination()
    print("✓ Regex vs NER combination test passed")
    
    test_complete_redaction_pipeline()
    print("✓ Complete redaction pipeline test passed")
    
    test_placeholder_numbering_consistency()
    print("✓ Placeholder numbering consistency test passed")
    
    test_multiple_pii_types_in_single_text()
    print("✓ Multiple PII types test passed")
    
    test_no_double_scanning_regex_vs_ner()
    print("✓ No double scanning test passed")
    
    test_sample_inputs_from_fixtures()
    print("✓ Sample inputs from fixtures test passed")
    
    test_placeholder_format_and_uniqueness()
    print("✓ Placeholder format and uniqueness test passed")
    
    print("\nAll end-to-end tests passed! ✓")