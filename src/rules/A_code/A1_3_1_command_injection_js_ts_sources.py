import re
from typing import Set


class JsTsSourceMixin:
    _JS_EXTERNAL_SOURCE_TOKENS = {
        "req.query",
        "req.body",
        "req.params",
        "req.headers",
        "request.query",
        "request.body",
        "request.params",
        "request.headers",
        "ctx.query",
        "ctx.request.body",
        "process.argv",
        "process.env",
    }
    _JS_SANITIZER_CALLS = {
        "shellEscape",
        "escapeShellArg",
        "shellQuote.quote",
        "quote",
    }

    @staticmethod
    def _contains_tainted_token(text: str, tainted_names: Set[str]) -> bool:
        for name in tainted_names:
            if re.search(rf"\b{re.escape(name)}\b", text):
                return True
        return False

    def _js_has_external_input(self, text: str, tainted_names: Set[str]) -> bool:
        if self._js_is_sanitized_expr(text):
            return False
        if any(token in text for token in self._JS_EXTERNAL_SOURCE_TOKENS):
            return True
        return self._contains_tainted_token(text, tainted_names)

    def _js_is_sanitized_expr(self, text: str) -> bool:
        stripped = text.strip().rstrip(";")
        return any(
            re.fullmatch(rf"{re.escape(name)}\s*\(.+\)", stripped)
            for name in self._JS_SANITIZER_CALLS
        )
