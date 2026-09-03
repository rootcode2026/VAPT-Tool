import json
from app.scanner.base import BaseScanner
from app.services.sast.analyzer import SASTAnalyzer


class SASTScanner(BaseScanner):
    name = "sast"
    category = "application_security"
    description = "Static Application Security Testing for Python source code"
    target_types = {"repository", "project", "directory"}
    input_type = "source_code"
    output_format = "json"
    capabilities = {"sast", "static_analysis", "python"}
    timeout = 120

    def scan(self, target: str) -> str:
        analyzer = SASTAnalyzer()
        result = analyzer.analyze(target)
        return json.dumps(result)
