"""AI Provider — mock, OpenAI-compatible, local."""
from __future__ import annotations

import os
import time
from abc import ABC, abstractmethod
from typing import Dict, Any

from app.core.config import settings

class AIProvider(ABC):
    provider_id: str = ""

    @abstractmethod
    def generate(self, prompt: str, context: Dict[str, Any], max_tokens: int = 1000) -> Dict[str, Any]:
        raise NotImplementedError

    def health(self) -> Dict[str, Any]:
        return {"provider": self.provider_id, "status": "ok"}

class MockAIProvider(AIProvider):
    provider_id = "mock"

    def generate(self, prompt: str, context: Dict[str, Any], max_tokens: int = 1000) -> Dict[str, Any]:
        # Deterministic mock referencing evidence
        findings = context.get("findings", [])[:3]
        assets = context.get("assets", [])[:2]
        citations = []
        for f in findings:
            citations.append(f"[FINDING:{f.get('id','unknown')}]")
        for a in assets:
            citations.append(f"[ASSET:{a.get('id','unknown')}]")
        # Simple classification based on prompt
        answer = f"Based on available evidence {', '.join(citations[:2]) if citations else '[no evidence]'}, this is an analysis of your security posture. "
        if "critical" in prompt.lower():
            answer += "Critical findings require immediate attention. "
        if "cloud" in prompt.lower():
            answer += "Cloud exposure increases priority. "
        # Distinguish fact/analysis/recommendation/unknown
        response = {
            "answer": answer[:2000],
            "confidence": "medium" if findings else "low",
            "claims": [
                {"claim": "Finding severity reflects risk", "evidence": citations[:1], "type": "KNOWN"},
                {"claim": "Exposure increases priority", "evidence": citations[1:2] if len(citations)>1 else [], "type": "INFERRED"},
            ],
            "evidence": citations,
            "recommendations": ["Review finding evidence and retest after remediation"],
            "limitations": "Mock provider — limited to supplied context; does not access external data.",
        }
        return {
            "provider": "mock",
            "model": "mock-analyst",
            "output": response,
            "input_tokens": len(prompt)//4,
            "output_tokens": len(str(response))//4,
        }

class OpenAIProvider(AIProvider):
    provider_id = "openai"

    def generate(self, prompt: str, context: Dict[str, Any], max_tokens: int = 1000) -> Dict[str, Any]:
        api_key = settings.AI_API_KEY or os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("AI provider not configured")
        base_url = settings.AI_BASE_URL or "https://api.openai.com/v1"
        model = settings.AI_MODEL or "gpt-4o-mini"
        # Use requests for simplicity
        try:
            import requests
            # Build messages with trust boundaries
            messages = [
                {"role": "system", "content": "You are a security analyst assistant. Use only provided platform evidence. Cite findings/assets. Distinguish KNOWN/INFERRED/UNKNOWN. Never invent CVEs or credentials."},
                {"role": "user", "content": f"Context (trusted, sanitized, bounded): {str(context)[:4000]}\n\nQuestion: {prompt[:2000]}"},
            ]
            payload = {"model": model, "messages": messages, "max_tokens": min(max_tokens, settings.AI_MAX_TOKENS), "temperature": settings.AI_TEMPERATURE}
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            resp = requests.post(f"{base_url.rstrip('/')}/chat/completions", json=payload, headers=headers, timeout=settings.AI_TIMEOUT)
            if resp.status_code != 200:
                raise RuntimeError(f"Provider error {resp.status_code}")
            data = resp.json()
            text = data.get("choices", [{}])[0].get("message", {}).get("content", "")[:2000]
            return {
                "provider": "openai",
                "model": model,
                "output": {
                    "answer": text,
                    "confidence": "medium",
                    "claims": [],
                    "evidence": [],
                    "recommendations": [],
                    "limitations": "External provider; evidence-grounded.",
                },
                "input_tokens": data.get("usage", {}).get("prompt_tokens", 0),
                "output_tokens": data.get("usage", {}).get("completion_tokens", 0),
            }
        except Exception as e:
            raise RuntimeError(f"AI provider error: {str(e)[:200]}")

class AIProviderRegistry:
    _providers = {
        "mock": MockAIProvider(),
        "openai": OpenAIProvider(),
        "local": MockAIProvider(),
    }

    @classmethod
    def get(cls, name: str) -> AIProvider:
        n = (name or "mock").lower()
        return cls._providers.get(n) or cls._providers["mock"]

    @classmethod
    def list(cls):
        return list(cls._providers.keys())

def get_ai_provider() -> AIProvider:
    if not settings.AI_ENABLED:
        return MockAIProvider()  # still mock but caller should check AI_ENABLED
    return AIProviderRegistry.get(settings.AI_PROVIDER)
