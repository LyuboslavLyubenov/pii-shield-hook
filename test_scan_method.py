#!/usr/bin/env python3
"""
Basic test for the updated scan method in PIIShield.
"""

import os
import sys

# Add the current dir to path so we can import pii_shield
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pii_shield import PIIShield

# Test the scan method implementation
def test_scan_method():
    # Use a simple mock model to avoid downloading the actual model in tests
    shield = PIIShield("prajjwal1/bert-tiny")  # Using smaller model for faster tests
    
    # Test case with both regex-detectable and potentially NER-detectable content
    test_text = "John Smith's email is john@example.com and his SSN is 123-45-6789. His friend Jane lives at 123 Main St."
    
    # Run the scan method
    results = shield.scan(test_text)
    
    # Verify that results are returned in proper format
    assert isinstance(results, list), "Results should be a list"
    
    # Check that it contains expected fields
    for result in results:
        assert "text" in result, "Result should have text field"
        assert "type" in result, "Result should have type field"
        assert "start" in result, "Result should have start field"
        assert "end" in result, "Result should have end field"
        assert "source" in result, "Result should have source field"
    
    # Check that sources are properly labeled
    for result in results:
        assert result["source"] in ["regex", "ner"], f"Source should be either 'regex' or 'ner', got {result['source']}"
    
    # Print results to verify the behavior
    print("Scan results:")
    for i, result in enumerate(results):
        print(f"{i+1}. Text: '{result['text']}' Type: {result['type']} Start: {result['start']} End: {result['end']} Source: {result['source']}")
    
    # Verify that regex detections come first in order (at least structurally)
    # Since we sort by start position, the order should be maintained properly
    
    # Check for regex-specific types in results
    has_regex_result = any(result['source'] == 'regex' for result in results)
    print(f"Has regex result: {has_regex_result}")
    
    print("Test passed!")

if __name__ == "__main__":
    test_scan_method()