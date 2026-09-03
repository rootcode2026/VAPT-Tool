import tempfile, json
from pathlib import Path
from app.scanner.pipeline import ScannerPipeline

def test_sast_through_pipeline(tmp_path):
    (tmp_path / "a.py").write_text('password = "secret123"\n')
    pipeline = ScannerPipeline()
    result = pipeline.run("sast", str(tmp_path))
    assert result["scanner"] == "sast"
    assert result["status"] == "completed"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["scanner"] == "sast"
