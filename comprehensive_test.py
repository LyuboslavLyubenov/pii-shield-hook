#!/usr/bin/env python3
"""
Comprehensive test for the updated scan method in PIIShield
that verifies all acceptance criteria are met.
"""

import os
import sys

# Add the current dir to path so we can import pii_shield
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pii_shield import PIIShield


def test_acceptance_criteria():
    """Test that all acceptance criteria are satisfied"""
    shield = PIIShield("prajjwal1/bert-tiny")  # Using smaller model for faster tests
    
    # Test case with both regex and potential NER detectable content
    # Mix of structured patterns (which regex should catch) and unstructured patterns (NER should catch unless regex already got them)
    test_text = "John Smith's API key is sk-test1234567890abcdef and his email is john@example.com. Jane Doe has a SSN 987-65-4321 and lives at 123 Main Street."
    
    # Run the scan method
    results = shield.scan(test_text)
    
    print("All results:")
    for i, result in enumerate(results):
        print(f"{i+1}. '{result['text']}' ({result['type']}) pos:[{result['start']}-{result['end']}] source:{result['source']}")

    # Criteria 1: "Scan method runs regex scanning first, then NER to catch any undetected items"
    print("\n--- Testing criteria 1: Regex runs first, then NER ---")
    regex_results = [r for r in results if r['source'] == 'regex']
    ner_results = [r for r in results if r['source'] == 'ner']
    print(f"Found {len(regex_results)} regex results and {len(ner_results)} NER results")
    assert len(regex_results) > 0, "Should have regex results"
    assert len(ner_results) > 0, "Should have NER results (unstructured PII)"
    print("✓ Criterion 1 satisfied: Both regex and NER results present")

    # Criteria 2: "Avoids duplicate detections by filtering NER results that overlap with regex results"
    print("\n--- Testing criteria 2: No overlaps between regex and NER results ---")
    overlap_count = 0
    for regex_r in regex_results:
        for ner_r in ner_results:
            # Check if intervals [start, end) overlap: start1 < end2 AND start2 < end1
            if (regex_r['start'] < ner_r['end'] and ner_r['start'] < regex_r['end']):
                print(f"  WARNING: Overlap found: '{regex_r['text']}'[{regex_r['start']}-{regex_r['end']}] <-regex |-> "
                      f"NER[{ner_r['start']}-{ner_r['end']}] '{ner_r['text']}'")
                overlap_count += 1
    assert overlap_count == 0, f"There should be no overlaps between regex and NER results, found {overlap_count}"
    print("✓ Criterion 2 satisfied: No overlaps between regex and NER results")

    # Criteria 3: "Returns combined list of findings maintaining correct order for redaction application"
    print("\n--- Testing criteria 3: Results are in correct order (by start position) ---")
    positions_in_order = [r['start'] for r in results]
    print(f"Positions: {positions_in_order}")
    is_ordered = all(positions_in_order[i] <= positions_in_order[i+1] for i in range(len(positions_in_order)-1))
    assert is_ordered, f"Results should be sorted by start position, got: {positions_in_order}"
    print("✓ Criterion 3 satisfied: Results ordered by start position")

    # Criteria 4: "Results include appropriate source field ('regex' or 'ner')"
    print("\n--- Testing criteria 4: Each result has appropriate source field ---")
    invalid_sources = [r for r in results if r['source'] not in ['regex', 'ner']]
    assert len(invalid_sources) == 0, f"All results should have 'regex' or 'ner' source, found: {[r['source'] for r in invalid_sources]}"
    print("✓ Criterion 4 satisfied: All results have valid 'regex' or 'ner' source field")
    
    # Additional verification - checking that specific types are marked with the right source
    print("\n--- Verifying that structured patterns are correctly labeled as 'regex' ---")
    emails = [r for r in results if r['type'] == 'EMAIL']
    ssns = [r for r in results if r['type'] == 'SSN']
    
    for email in emails:
        assert email['source'] == 'regex', f"Email should be detected by regex, got {email['source']} for '{email['text']}'"
    for ssn in ssns:
        assert ssn['source'] == 'regex', f"SSN should be detected by regex, got {ssn['source']} for '{ssn['text']}'"
    
    print("✓ Verification passed: Structured patterns (emails, SSNs) correctly marked as 'regex'")
    
    print("\n🎉 All acceptance criteria satisfied!")
    
    
def test_edge_cases():
    """Test edge cases"""
    shield = PIIShield("prajjwal1/bert-tiny")
    
    print("--- Testing edge case: No PII ---")
    text_no_pii = "This is ordinary text with no PII."
    results = shield.scan(text_no_pii)
    assert len(results) == 0, f"Should have no results for PII-free text, got: {results}"
    print("✓ No PII test passed")
    
    print("--- Testing edge case: Only regex hits ---")
    text_only_regex = "My email is test@example.com and my SSN is 123-45-6789"
    results = shield.scan(text_only_regex)
    sources = [r['source'] for r in results]
    assert all(s == 'regex' for s in sources), f"All results should be from regex for structured patterns, got: {sources}"
    print("✓ Only regex hits test passed")
                
    print("\n🎉 All edge cases passed!")


if __name__ == "__main__":
    print("Testing scan method with acceptance criteria...")
    test_acceptance_criteria()
    test_edge_cases()
    print("\n✅ All tests passed! Implementation satisfies all acceptance criteria.")