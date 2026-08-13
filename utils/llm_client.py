"""
LLM Client — Unified interface for Large Language Model APIs.

Supports:
- Anthropic Claude API (primary)
- OpenAI API (fallback / cost-sensitive tasks)
- Custom OpenAI-compatible endpoints

Design principles:
1. Single interface for all providers — switch via config
2. Automatic retry with exponential backoff
3. Token counting and cost tracking per call
4. Prompt template loading and variable substitution
5. Context window management (truncation warnings)
"""

import os
import re
import time
import json
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

from .logger import get_logger

logger = get_logger("agent.llm_client")


@dataclass
class LLMResponse:
    """Standardized response from any LLM provider."""

    content: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cost_usd: float
    latency_seconds: float
    finish_reason: str = "stop"
    raw_response: Optional[Dict] = None


class LLMClient:
    """
    Unified LLM API client.

    Usage:
        client = LLMClient(config)
        response = client.chat(
            messages=[{"role": "user", "content": "Analyze this code..."}],
            system_prompt="You are a security analyst...",
        )
        print(f"Cost: ${response.cost_usd:.4f}, Tokens: {response.total_tokens}")
    """

    # Approximate cost per 1K tokens (updated as of 2025)
    COST_PER_1K = {
        "claude-opus-5": {"prompt": 0.015, "completion": 0.075},
        "claude-sonnet-5": {"prompt": 0.003, "completion": 0.015},
        "claude-fable-5": {"prompt": 0.001, "completion": 0.005},
        "claude-haiku-4-5-20251001": {"prompt": 0.0008, "completion": 0.004},
        "gpt-4o": {"prompt": 0.0025, "completion": 0.010},
        "gpt-4o-mini": {"prompt": 0.00015, "completion": 0.0006},
    }

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the LLM client.

        Args:
            config: LLM configuration dict from config.yaml
        """
        self.config = config
        self.provider = config.get("provider", "anthropic")
        self.model = config.get("model", "claude-sonnet-5")
        self.max_tokens = config.get("max_tokens", 4096)
        self.temperature = config.get("temperature", 0.1)
        self.timeout = config.get("timeout", 120)
        self.max_retries = config.get("max_retries", 3)
        self.context_limit = config.get("context_limit", 8000)

        # Resolve API key from env var or direct value
        api_key_raw = config.get("api_key", "")
        self.api_key = self._resolve_env_var(api_key_raw)

        # Track cumulative usage
        self.total_cost_usd = 0.0
        self.total_calls = 0
        self.total_tokens = 0

        # Lazy-loaded clients
        self._anthropic_client = None
        self._openai_client = None

        # Prompt template cache
        self._prompt_cache: Dict[str, str] = {}
        self._prompts_dir = Path("prompts")

        self._init_client()

    def _resolve_env_var(self, value: str) -> str:
        """Resolve ${ENV_VAR} patterns in config values."""
        if value.startswith("${") and value.endswith("}"):
            env_var = value[2:-1]
            return os.environ.get(env_var, "")
        return value

    def _init_client(self):
        """Initialize the appropriate API client."""
        if not self.api_key:
            logger.warning(
                f"No API key found for provider '{self.provider}'. "
                f"LLM calls will fail. Set the appropriate environment variable."
            )
            return

        try:
            if self.provider == "anthropic":
                import anthropic

                self._anthropic_client = anthropic.Anthropic(
                    api_key=self.api_key,
                    timeout=self.timeout,
                    max_retries=self.max_retries,
                )
                logger.info(f"Anthropic client initialized (model: {self.model})")

            elif self.provider in ("openai", "custom"):
                from openai import OpenAI

                base_url = self.config.get("base_url")
                if base_url:
                    self._openai_client = OpenAI(
                        api_key=self.api_key,
                        base_url=base_url,
                        timeout=self.timeout,
                        max_retries=self.max_retries,
                    )
                else:
                    self._openai_client = OpenAI(
                        api_key=self.api_key,
                        timeout=self.timeout,
                        max_retries=self.max_retries,
                    )
                logger.info(f"OpenAI client initialized (model: {self.model})")

            else:
                raise ValueError(f"Unsupported LLM provider: {self.provider}")

        except ImportError as e:
            logger.error(f"Failed to import client library for '{self.provider}': {e}")
            logger.error("Install with: pip install anthropic  or  pip install openai")

    def _estimate_tokens(self, text: str) -> int:
        """
        Rough token estimation (4 chars ≈ 1 token for English).
        Falls back to tiktoken if available.
        """
        try:
            import tiktoken

            enc = tiktoken.get_encoding("cl100k_base")
            return len(enc.encode(text))
        except ImportError:
            return len(text) // 4

    def _calculate_cost(self, model: str, prompt_tokens: int, completion_tokens: int) -> float:
        """Calculate USD cost based on token usage."""
        model_costs = self.COST_PER_1K.get(model)
        if not model_costs:
            # Estimate based on model family
            if "opus" in model:
                model_costs = {"prompt": 0.015, "completion": 0.075}
            elif "sonnet" in model:
                model_costs = {"prompt": 0.003, "completion": 0.015}
            elif "haiku" in model:
                model_costs = {"prompt": 0.0008, "completion": 0.004}
            elif "gpt-4o-mini" in model:
                model_costs = {"prompt": 0.00015, "completion": 0.0006}
            elif "gpt-4" in model:
                model_costs = {"prompt": 0.0025, "completion": 0.010}
            else:
                model_costs = {"prompt": 0.001, "completion": 0.005}

        cost = (prompt_tokens / 1000) * model_costs["prompt"] + (
            completion_tokens / 1000
        ) * model_costs["completion"]
        return cost

    # --- Prompt template system ---

    def load_prompt(self, template_name: str, **variables) -> str:
        """
        Load a prompt template and substitute variables.

        Templates are stored in prompts/*.txt with {variable} placeholders.

        Args:
            template_name: Name of the template file (without .txt extension)
            **variables: Key-value pairs for substitution

        Returns:
            Rendered prompt string

        Example:
            prompt = client.load_prompt("analyzer", target_url="example.com", vuln_type="sqli")
        """
        if template_name not in self._prompt_cache:
            template_path = self._prompts_dir / f"{template_name}.txt"
            if template_path.exists():
                self._prompt_cache[template_name] = template_path.read_text(encoding="utf-8")
            else:
                logger.warning(f"Prompt template not found: {template_path}")
                return ""

        template = self._prompt_cache.get(template_name, "")
        try:
            # Use safe string formatting (not eval)
            result = template
            for key, value in variables.items():
                result = result.replace("{" + key + "}", str(value))
            return result
        except Exception as e:
            logger.error(f"Failed to render prompt template '{template_name}': {e}")
            return template

    # --- Main chat interface ---

    def chat(
        self,
        messages: List[Dict[str, str]],
        system_prompt: str = "",
        model: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> LLMResponse:
        """
        Send a chat completion request to the configured LLM.

        Args:
            messages: List of {"role": "...", "content": "..."} dictionaries
            system_prompt: System-level instruction (Claude) or system message
            model: Override default model
            max_tokens: Override default max_tokens
            temperature: Override default temperature

        Returns:
            LLMResponse with content, tokens, and cost

        Raises:
            RuntimeError: If the LLM API call fails after retries
        """
        model = model or self.model
        max_tokens = max_tokens or self.max_tokens
        temperature = temperature if temperature is not None else self.temperature

        # Warn if context is very long
        total_input = system_prompt + "".join(m.get("content", "") for m in messages)
        estimated_tokens = self._estimate_tokens(total_input)
        if estimated_tokens > self.context_limit * 0.8:
            logger.warning(
                f"Input is {estimated_tokens} tokens ({(estimated_tokens / self.context_limit) * 100:.0f}% "
                f"of {self.context_limit} context limit). Consider truncating."
            )

        start_time = time.time()

        try:
            if self.provider == "anthropic":
                response = self._call_anthropic(
                    messages, system_prompt, model, max_tokens, temperature
                )
            elif self.provider in ("openai", "custom"):
                response = self._call_openai(
                    messages, system_prompt, model, max_tokens, temperature
                )
            else:
                raise ValueError(f"Unsupported provider: {self.provider}")

        except Exception as e:
            logger.error(f"LLM call failed (provider={self.provider}, model={model}): {e}")
            raise RuntimeError(f"LLM API call failed: {e}") from e

        # Track cumulative stats
        self.total_calls += 1
        self.total_tokens += response.total_tokens
        self.total_cost_usd += response.cost_usd

        logger.debug(
            f"LLM call: {response.total_tokens} tokens, "
            f"${response.cost_usd:.4f}, "
            f"{response.latency_seconds:.1f}s"
        )

        return response

    def chat_with_tools(
        self,
        messages: List[Dict[str, Any]],
        system_prompt: str = "",
        tools: Optional[List[Dict]] = None,
        model: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> LLMResponse:
        """
        Chat completion with function calling (OpenAI-compatible APIs).

        Args:
            messages: Conversation history (may include assistant tool_calls
                      and tool role messages)
            system_prompt: System instruction
            tools: OpenAI-style tool schemas
            model/max_tokens/temperature: overrides

        Returns:
            LLMResponse with content, tool_calls, tokens, cost
        """
        model = model or self.model
        max_tokens = max_tokens or self.max_tokens
        temperature = temperature if temperature is not None else self.temperature

        start = time.time()

        if self.provider not in ("openai", "custom"):
            # Anthropic fallback: no function calling, just regular chat
            return self.chat(messages, system_prompt, model, max_tokens, temperature)

        try:
            openai_messages = []
            if system_prompt:
                openai_messages.append({"role": "system", "content": system_prompt})
            openai_messages.extend(messages)

            kwargs: Dict[str, Any] = {
                "model": model,
                "messages": openai_messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }
            if tools:
                kwargs["tools"] = tools
                kwargs["tool_choice"] = "auto"

            resp = self._openai_client.chat.completions.create(**kwargs)

            latency = time.time() - start
            choice = resp.choices[0]
            msg = choice.message

            # Extract tool calls
            tool_calls = []
            if msg.tool_calls:
                import json as _json
                for tc in msg.tool_calls:
                    try:
                        args = _json.loads(tc.function.arguments) if tc.function.arguments else {}
                    except _json.JSONDecodeError:
                        args = {}
                    tool_calls.append({
                        "id": tc.id,
                        "name": tc.function.name,
                        "arguments": args,
                    })

            prompt_tokens = resp.usage.prompt_tokens
            completion_tokens = resp.usage.completion_tokens

            content = msg.content or ""
            # Reasoning model fallback
            reasoning = getattr(msg, "reasoning_content", None)
            if not content and reasoning:
                content = f"(reasoning truncated: {reasoning[-200:]})"

            response = LLMResponse(
                content=content,
                model=model,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
                cost_usd=self._calculate_cost(model, prompt_tokens, completion_tokens),
                latency_seconds=latency,
                finish_reason=choice.finish_reason or "stop",
            )
            response.tool_calls = tool_calls  # type: ignore

            # Track usage
            self.total_calls += 1
            self.total_tokens += response.total_tokens
            self.total_cost_usd += response.cost_usd

            logger.debug(
                f"LLM call (tools): {response.total_tokens} tokens, "
                f"{len(tool_calls)} tool calls, ${response.cost_usd:.4f}"
            )
            return response

        except Exception as e:
            logger.error(f"LLM tool call failed: {e}")
            raise

    def _call_anthropic(
        self,
        messages: List[Dict],
        system_prompt: str,
        model: str,
        max_tokens: int,
        temperature: float,
    ) -> LLMResponse:
        """Call Anthropic Claude API."""
        import anthropic

        start = time.time()

        # Convert messages to Anthropic format
        anthropic_messages = []
        for msg in messages:
            anthropic_messages.append({
                "role": msg["role"],
                "content": msg["content"],
            })

        resp = self._anthropic_client.messages.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_prompt if system_prompt else anthropic.NOT_GIVEN,
            messages=anthropic_messages,
        )

        latency = time.time() - start

        content = ""
        for block in resp.content:
            if hasattr(block, "text"):
                content += block.text

        prompt_tokens = resp.usage.input_tokens
        completion_tokens = resp.usage.output_tokens

        return LLMResponse(
            content=content,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            cost_usd=self._calculate_cost(model, prompt_tokens, completion_tokens),
            latency_seconds=latency,
            finish_reason=resp.stop_reason or "stop",
        )

    def _call_openai(
        self,
        messages: List[Dict],
        system_prompt: str,
        model: str,
        max_tokens: int,
        temperature: float,
    ) -> LLMResponse:
        """Call OpenAI API (or compatible endpoint)."""
        start = time.time()

        openai_messages = []
        if system_prompt:
            openai_messages.append({"role": "system", "content": system_prompt})
        openai_messages.extend(messages)

        resp = self._openai_client.chat.completions.create(
            model=model,
            messages=openai_messages,
            max_tokens=max_tokens,
            temperature=temperature,
        )

        latency = time.time() - start

        choice = resp.choices[0]
        content = choice.message.content or ""

        # Reasoning models: content may be empty when all tokens
        # went to reasoning_content. Fall back gracefully.
        reasoning = getattr(choice.message, "reasoning_content", None)
        if not content and reasoning:
            content = f"(reasoning truncated: {reasoning[-200:]})"

        prompt_tokens = resp.usage.prompt_tokens
        completion_tokens = resp.usage.completion_tokens

        return LLMResponse(
            content=content,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            cost_usd=self._calculate_cost(model, prompt_tokens, completion_tokens),
            latency_seconds=latency,
            finish_reason=choice.finish_reason or "stop",
        )

    def get_usage_summary(self) -> Dict[str, Any]:
        """Get cumulative usage statistics."""
        return {
            "total_calls": self.total_calls,
            "total_tokens": self.total_tokens,
            "total_cost_usd": round(self.total_cost_usd, 4),
            "provider": self.provider,
            "model": self.model,
        }
