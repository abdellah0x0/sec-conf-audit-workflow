from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import DeanonymizeEngine
from presidio_anonymizer.entities import OperatorConfig
from presidio_analyzer import Pattern, PatternRecognizer
import re
import math
from collections import Counter
import os

from dotenv import load_dotenv

def shannon_entropy(s: str) -> float:
    if not s:
        return 0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


class HighEntropyRecognizer(PatternRecognizer):
    def __init__(self):
        patterns = [
            Pattern(name="base64_blob", regex=r'[A-Za-z0-9+/_\-=]{16,}', score=0.6)
        ]
        super().__init__(supported_entity="ENCRYPTED_BLOB", patterns=patterns)

    def validate_result(self, pattern_text):
        return shannon_entropy(pattern_text) >= 4.0  # extra filter beyond regex

load_dotenv()
key = os.getenv("KEY")


def deanonymize(text):
    
    analyzer = AnalyzerEngine()      
    analyzer.registry.add_recognizer(HighEntropyRecognizer())


    # Detect entities
    results = analyzer.analyze(
        text=text,
        entities=["ENCRYPTED_BLOB"],
        language="en"
    )

    # Deanonymize detected entities 
    try :
        deanonymizer_engine = DeanonymizeEngine()
        deanonymized = deanonymizer_engine.deanonymize(
            text, 
            results, 
            {"DEFAULT": OperatorConfig("decrypt", {"key": key})}
        )
        return deanonymized.text
    
    except Exception as e:
        return text
