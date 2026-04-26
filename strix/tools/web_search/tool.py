"""``web_search`` — Perplexity-backed security-focused web search."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import requests
from agents import RunContextWrapper, function_tool

from strix.config import load_settings


logger = logging.getLogger(__name__)


_SYSTEM_PROMPT = """You are assisting a cybersecurity agent specialized in vulnerability scanning
and security assessment running on Kali Linux. When responding to search queries:

1. Prioritize cybersecurity-relevant information including:
   - Vulnerability details (CVEs, CVSS scores, impact)
   - Security tools, techniques, and methodologies
   - Exploit information and proof-of-concepts
   - Security best practices and mitigations
   - Penetration testing approaches
   - Web application security findings

2. Provide technical depth appropriate for security professionals
3. Include specific versions, configurations, and technical details when available
4. Focus on actionable intelligence for security assessment
5. Cite reliable security sources (NIST, OWASP, CVE databases, security vendors)
6. When providing commands or installation instructions, prioritize Kali Linux compatibility
   and use apt package manager or tools pre-installed in Kali
7. Be detailed and specific - avoid general answers. Always include concrete code examples,
   command-line instructions, configuration snippets, or practical implementation steps
   when applicable

Structure your response to be comprehensive yet concise, emphasizing the most critical
security implications and details."""


def _do_search(query: str) -> dict[str, Any]:
    api_key = load_settings().integrations.perplexity_api_key
    if not api_key:
        logger.warning("web_search invoked without PERPLEXITY_API_KEY configured")
        return {
            "success": False,
            "message": "PERPLEXITY_API_KEY environment variable not set",
            "results": [],
        }
    logger.info("web_search query (len=%d): %s", len(query), query[:120])

    url = "https://api.perplexity.ai/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": query},
        ],
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=300)
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
    except requests.exceptions.Timeout:
        logger.warning("web_search timed out")
        return {"success": False, "message": "Request timed out", "results": []}
    except requests.exceptions.RequestException as e:
        logger.exception("web_search API request failed")
        return {"success": False, "message": f"API request failed: {e!s}", "results": []}
    except KeyError as e:
        logger.exception("web_search response shape unexpected")
        return {
            "success": False,
            "message": f"Unexpected API response format: missing {e!s}",
            "results": [],
        }
    except Exception as e:
        logger.exception("web_search failed")
        return {"success": False, "message": f"Web search failed: {e!s}", "results": []}
    else:
        return {
            "success": True,
            "query": query,
            "content": content,
            "message": "Web search completed successfully",
        }


# Perplexity request timeout is 300s; give the SDK a slightly larger
# budget so the round-trip + JSON decode doesn't push us over.
@function_tool(timeout=330)
async def web_search(ctx: RunContextWrapper, query: str) -> str:
    """Real-time web search via Perplexity — your primary research tool.

    Use it liberally for anything that's not in your training data:

    - Current CVEs, advisories, and 0-days for a specific
      service/version (``OpenSSH 9.6 RCE``, ``Jenkins 2.401.3 auth
      bypass``).
    - Latest WAF / EDR bypass techniques (``Cloudflare WAF SQLi
      bypass 2025``, ``CrowdStrike Falcon evasion``).
    - Tool documentation, flag references, payload galleries.
    - Target reconnaissance / OSINT (company tech stack, leaked
      credentials, exposed assets).
    - Cloud-provider misconfiguration patterns
      (Azure/AWS/GCP-specific attack paths).
    - Bug-bounty writeups and security research papers.
    - Compliance frameworks and CWE/CVSS guidance.
    - Picking the right Python lib / Kali tool for a job (``best 2025
      lib for JWT alg-confusion``).
    - When stuck — looking up the exact error message, ``Access
      denied`` quirks, kernel-specific local-privesc exploits.

    Be specific: include version numbers, error messages, target
    technology, and the exact problem you're stuck on. The more context
    in the query, the more actionable the answer. Vague queries get
    generic answers.

    A security-focused system prompt biases responses toward CVEs,
    exploits, Kali-compatible tooling, and concrete code/command
    examples.

    Args:
        query: The search query — a full sentence with version numbers,
            target tech, and the specific question. Treat it like a
            ticket title for a senior security engineer.
    """
    result = await asyncio.to_thread(_do_search, query)
    return json.dumps(result, ensure_ascii=False, default=str)
