from __future__ import annotations

from typing import Any, Dict, Iterable

from codex_llm import codex_chat_json

class LLMClient:
    def __init__(self, api_key: str | None = None, model: str = "gpt-5.4-mini"):
        self.model = model
    
    def analyze_code(self, prompt: str, method_code: str) -> Dict:
        """
        分析代码片段是否调用了大模型
        
        Args:
            prompt: 提示词模板
            method_code: 要分析的代码片段
            
        Returns:
            大模型返回的JSON响应
        """
        full_prompt = prompt.format(method_code=method_code)
        
        return codex_chat_json(full_prompt, model=self.model)

    def chat_completion(
        self,
        messages: Iterable[dict[str, Any]],
        *,
        model: str | None = None,
        temperature: float = 0,
        max_tokens: int = 1024,
        response_format: dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Compatibility adapter for the OpenAI-style calls used by validators."""
        prompt = "\n\n".join(str(message.get("content", "")) for message in messages)
        return codex_chat_json(prompt, model=self.model)
