import os
from dotenv import load_dotenv
from presidio_analyzer import AnalyzerEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

load_dotenv()
key = os.getenv("KEY")


provider = AnalyzerEngineProvider(analyzer_engine_conf_file="anonymization/analyzer_config.yaml")
analyzer = provider.create_engine()
anonymizer_eng = AnonymizerEngine()


def anonymizer(text: str):
    analyzer_results = analyzer.analyze(
        text=text,
        language="en",
        score_threshold=0.0,
    )

    result = anonymizer_eng.anonymize(
        text=text,
        analyzer_results=analyzer_results,
        operators={"DEFAULT": OperatorConfig("encrypt", {"key": key})},
    )

    return result.text


