import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import httpx

from app.config import settings
from app.models.enums import OverallStatus, SeverityLevel, SourceStatus
from app.models.schemas import VulnerabilityResponse
from app.models.triage import ModelInvocationStatus, TriagePriority

logger = logging.getLogger(__name__)


class StrandsDeciderError(Exception):
    """Base exception for Strands Decider 2B client failures."""

    def __init__(self, message: str, status_code: int = 503):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class StrandsDeciderUnavailableError(StrandsDeciderError):
    """Raised when Strands Decider is not reachable or cannot execute on the host."""
    pass


class StrandsDeciderTimeoutError(StrandsDeciderError):
    """Raised when Strands Decider inference times out."""
    pass


class StrandsDeciderValidationError(StrandsDeciderError):
    """Raised when Strands Decider returns malformed or unexpected responses."""
    pass


@dataclass
class DeciderEvaluation:
    """Validated structured decision output from Strands Decider 2B System-1 inference."""

    priority: TriagePriority
    priority_probabilities: Dict[str, float]
    confidence: float
    confidence_is_calibrated: bool
    emergency_mitigation_noul: float
    requires_emergency_mitigation: bool
    model_id: str
    status: ModelInvocationStatus = ModelInvocationStatus.SUCCESS
    raw_response: Optional[Dict[str, Any]] = None


# Shared model engine cache: key is f"{model_id}::{device}"
_LOCAL_ENGINE_CACHE: Dict[str, Any] = {}
_LOCAL_ENGINE_LOAD_LOCK = asyncio.Lock()
_LOCAL_ENGINE_INFERENCE_LOCK = asyncio.Lock()


def clear_local_engine_cache() -> None:
    """Clear cached in-process model engines (used for deterministic testing and clean reloads)."""
    global _LOCAL_ENGINE_CACHE
    _LOCAL_ENGINE_CACHE.clear()


# Official Strands Decider Questions Specification
PRIORITY_QUESTION_CRITERIA = {
    "Critical": "Confirmed active in-the-wild exploitation in CISA KEV with critical CVSS (>=8.5) or severe weaponization requiring emergency response.",
    "High": "Elevated exploit potential, CVSS >= 7.0, or high EPSS probability requiring expedited patching within operational SLA.",
    "Medium": "Moderate severity without confirmed active exploitation; standard patch deployment lifecycle.",
    "Low": "Low severity rating with minimal predictive threat telemetry; routine maintenance.",
}

# In official strands_decider schema, NoulQuestion criteria keys must be a subset of {"true", "false"}
EMERGENCY_MITIGATION_CRITERIA = {
    "true": "Active in-the-wild exploitation or imminent weaponization requiring immediate operational isolation or out-of-band mitigation.",
    "false": "Standard or expedited patch assessment without emergency operational isolation.",
}


class StrandsDeciderClient:
    """Dedicated adapter for genuine Strands Decider 2B System-1 evaluation.

    Supports:
    1. Verified remote HTTP service (POST /v1/systemone per strands_decider.server)
    2. Local in-process engine via strands_decider.load_engine()
    3. Injected engine/client mock for deterministic offline unit testing
    """

    def __init__(
        self,
        model_id: Optional[str] = None,
        server_url: Optional[str] = None,
        mode: Optional[str] = None,
        device: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
        max_retries: Optional[int] = None,
        injected_engine: Optional[Any] = None,
        injected_http_client: Optional[httpx.AsyncClient] = None,
    ):
        self.model_id = model_id or settings.strands_decider_model_id
        self.server_url = (server_url or settings.strands_decider_url or "http://127.0.0.1:8080").rstrip("/")
        self.mode = mode or settings.strands_decider_mode
        self.device = device or getattr(settings, "strands_decider_device", "auto")
        self.timeout_seconds = timeout_seconds or settings.strands_decider_timeout_seconds
        self.max_retries = max_retries if max_retries is not None else settings.max_decision_retries
        self._injected_engine = injected_engine
        self._injected_http_client = injected_http_client
        self._local_engine: Optional[Any] = None

    def _resolve_device(self) -> str:
        """Resolve the target PyTorch device for local inference."""
        if self.device and self.device.lower() != "auto":
            return self.device.lower()
        try:
            import torch
            if torch.cuda.is_available():
                return "cuda"
            if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                return "mps"
        except Exception:
            pass
        return "cpu"

    def format_evidence_state(self, resp: VulnerabilityResponse) -> str:
        """Format normalized threat intelligence into the official Strands Decider state context."""
        norm = resp.normalized
        prov = resp.provenance

        cvss_score = norm.cvss_score if norm and norm.cvss_score is not None else 0.0
        cvss_sev = norm.primary_severity.value if norm else "UNKNOWN"
        is_kev = prov.cisa_kev.is_listed
        epss_prob = prov.epss.probability if prov.epss.probability is not None else 0.0
        epss_percentile = prov.epss.percentile if prov.epss.percentile is not None else 0.0

        desc = (norm.description if norm else "No description available.").strip()
        # Truncate overly long descriptions for efficient prefix caching
        if len(desc) > 500:
            desc = desc[:497] + "..."

        lines = [
            f"Vulnerability Identifier: {resp.cve_id}",
            f"Description: {desc}",
            f"CVSS Base Score: {cvss_score:.1f} (Severity: {cvss_sev})",
            f"CISA KEV Listed: {'YES' if is_kev else 'NO'} (Status: {prov.cisa_kev.status.value})",
        ]
        if is_kev and prov.cisa_kev.date_added:
            lines.append(f"CISA KEV Date Added: {prov.cisa_kev.date_added}")
        if is_kev and prov.cisa_kev.known_ransomware_campaign_use:
            lines.append(f"Known Ransomware Campaign Use: {prov.cisa_kev.known_ransomware_campaign_use}")

        lines.append(f"EPSS Exploitation Probability (30-day): {epss_prob * 100:.2f}% (Percentile: {epss_percentile * 100:.1f}%)")
        if norm and norm.affected_cpe_count > 0:
            lines.append(f"Affected CPE Configurations: {norm.affected_cpe_count}")

        if resp.errors:
            lines.append(f"Telemetry Warnings: {'; '.join(resp.errors)}")

        return "\n".join(lines)

    def build_systemone_questions(self) -> Dict[str, Dict[str, Any]]:
        """Construct official Strands Decider Choice and Noul questions dictionary.

        Uses official field name 'instructions' and official criteria schema.
        """
        return {
            "priority": {
                "type": "choice",
                "instructions": "Assign the appropriate vulnerability triage priority based on the observed threat telemetry.",
                "criteria": PRIORITY_QUESTION_CRITERIA,
            },
            "requires_emergency_mitigation": {
                "type": "noul",
                "instructions": "Does this vulnerability require immediate out-of-band operational isolation or emergency mitigation?",
                "criteria": EMERGENCY_MITIGATION_CRITERIA,
            },
        }

    async def check_health(self) -> Dict[str, Any]:
        """Check availability and model metadata from the remote Strands Decider server (GET /health)."""
        url = f"{self.server_url}/health"
        timeout = min(self.timeout_seconds, 3.0)
        try:
            if self._injected_http_client:
                res = await self._injected_http_client.get(url, timeout=timeout)
            else:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    res = await client.get(url)

            if res.status_code == 200:
                data = res.json()
                is_ok = data.get("status") == "ok"
                return {
                    "reachable": is_ok,
                    "status": data.get("status", "ok" if is_ok else "unknown"),
                    "model": data.get("model") or data.get("checkpoint"),
                    "device": data.get("device"),
                    "raw": data,
                }
            return {
                "reachable": False,
                "status": f"HTTP {res.status_code}",
                "model": None,
                "device": None,
                "raw": None,
            }
        except httpx.ConnectError as e:
            return {
                "reachable": False,
                "status": f"Connection refused ({self.server_url})",
                "model": None,
                "device": None,
                "raw": None,
            }
        except httpx.TimeoutException:
            return {
                "reachable": False,
                "status": f"Health check timed out after {timeout}s",
                "model": None,
                "device": None,
                "raw": None,
            }
        except Exception as e:
            return {
                "reachable": False,
                "status": f"Health check error: {str(e)}",
                "model": None,
                "device": None,
                "raw": None,
            }

    async def evaluate(self, resp: VulnerabilityResponse) -> DeciderEvaluation:
        """Execute Strands Decider 2B System-1 inference."""
        # 1. Deterministic injected mock test path
        if self._injected_engine is not None:
            return await self._evaluate_injected(resp)

        # 2. Remote HTTP Server Path (POST /v1/systemone)
        if self.mode in ("remote", "auto"):
            try:
                return await self._evaluate_remote(resp)
            except StrandsDeciderValidationError:
                raise
            except (httpx.ConnectError, httpx.TimeoutException, StrandsDeciderError) as e:
                logger.warning("Strands Decider remote server (%s) unavailable: %s", self.server_url, str(e))
                if self.mode == "remote":
                    raise StrandsDeciderUnavailableError(
                        f"Strands Decider remote server at {self.server_url} is unavailable: {str(e)}"
                    ) from e
                # In auto mode, attempt local fallback if remote failed
                logger.info("Auto mode: Remote unavailable, attempting local engine...")

        # 3. Local In-Process SDK Path
        return await self._evaluate_local(resp)

    async def _evaluate_remote(self, resp: VulnerabilityResponse) -> DeciderEvaluation:
        """Call verified official Strands Decider HTTP server endpoint."""
        state_text = self.format_evidence_state(resp)
        questions_payload = self.build_systemone_questions()

        payload = {
            "state": state_text,
            "model": self.model_id,
            "questions": questions_payload,
        }

        attempt = 0
        last_error = ""

        while attempt <= self.max_retries:
            attempt += 1
            try:
                if self._injected_http_client:
                    client = self._injected_http_client
                    res = await client.post(
                        f"{self.server_url}/v1/systemone",
                        json=payload,
                        timeout=self.timeout_seconds,
                    )
                else:
                    async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                        res = await client.post(
                            f"{self.server_url}/v1/systemone",
                            json=payload,
                        )

                if res.status_code == 200:
                    data = res.json()
                    return self._parse_decider_response(data)

                if res.status_code == 404:
                    raise StrandsDeciderUnavailableError(
                        f"Strands Decider endpoint {self.server_url}/v1/systemone returned 404 Not Found."
                    )

                if res.status_code == 422:
                    raise StrandsDeciderValidationError(
                        f"Strands Decider server rejected request schema (HTTP 422): {res.text[:200]}"
                    )

                last_error = f"HTTP {res.status_code}: {res.text[:200]}"
                if res.status_code >= 500 and attempt <= self.max_retries:
                    await asyncio.sleep(settings.retry_backoff_factor ** attempt)
                    continue
                raise StrandsDeciderError(f"Strands Decider server error: {last_error}", status_code=res.status_code)

            except httpx.TimeoutException as e:
                last_error = f"Request timed out after {self.timeout_seconds}s (attempt {attempt}/{self.max_retries + 1})"
                logger.warning(last_error)
                if attempt <= self.max_retries:
                    await asyncio.sleep(settings.retry_backoff_factor ** attempt)
                    continue
                raise StrandsDeciderTimeoutError(last_error) from e

            except httpx.ConnectError as e:
                raise StrandsDeciderUnavailableError(
                    f"Connection refused to Strands Decider server at {self.server_url}: {str(e)}"
                ) from e

        raise StrandsDeciderError(f"Strands Decider remote invocation failed: {last_error}")

    async def _get_or_load_local_engine(self) -> Any:
        """Retrieve cached engine or load weights into process once with concurrency protection."""
        if self._local_engine is not None:
            return self._local_engine

        resolved_device = self._resolve_device()
        cache_key = f"{self.model_id}::{resolved_device}"

        async with _LOCAL_ENGINE_LOAD_LOCK:
            if cache_key in _LOCAL_ENGINE_CACHE:
                self._local_engine = _LOCAL_ENGINE_CACHE[cache_key]
                return self._local_engine

            loop = asyncio.get_running_loop()

            def _load():
                try:
                    import torch  # type: ignore # noqa: F401
                    from strands_decider.infer import load_engine  # type: ignore
                except (ImportError, OSError) as e:
                    err_msg = str(e)
                    if "4551" in err_msg:
                        platform_doc = (
                            "Local Strands Decider inference is unavailable on this host: "
                            "Windows native PyTorch DLL execution is blocked by OS security policy (WinError 4551). "
                            "To run genuine Strands Decider 2B live, connect to an official remote HTTP server: "
                            f"python -m strands_decider.server --model {self.model_id} --port 8080 "
                            "or run in an unconstrained Linux/WSL/container environment."
                        )
                    else:
                        platform_doc = (
                            "Local Strands Decider inference is unavailable on this host: "
                            f"native PyTorch loader failure [{err_msg}]. "
                            "To run genuine Strands Decider 2B live, connect to an official remote HTTP server: "
                            f"python -m strands_decider.server --model {self.model_id} --port 8080 "
                            "or run in an unconstrained Linux/WSL/container environment."
                        )
                    logger.warning("%s", platform_doc)
                    raise StrandsDeciderUnavailableError(platform_doc) from e

                logger.info(
                    "Loading local Strands Decider weights for checkpoint '%s' on device '%s'...",
                    self.model_id,
                    resolved_device,
                )
                try:
                    loaded = load_engine(self.model_id, device=resolved_device)
                    logger.info("Local Strands Decider checkpoint '%s' loaded successfully.", self.model_id)
                    return loaded
                except (ImportError, OSError) as e:
                    err_msg = str(e)
                    if "4551" in err_msg:
                        platform_doc = (
                            "Local Strands Decider inference is unavailable on this host: "
                            "Windows native PyTorch DLL execution is blocked by OS security policy (WinError 4551). "
                            "To run genuine Strands Decider 2B live, connect to an official remote HTTP server: "
                            f"python -m strands_decider.server --model {self.model_id} --port 8080 "
                            "or run in an unconstrained Linux/WSL/container environment."
                        )
                    else:
                        platform_doc = (
                            "Local Strands Decider inference is unavailable on this host: "
                            f"failed to load model weights [{err_msg}]. "
                            "To run genuine Strands Decider 2B live, connect to an official remote HTTP server: "
                            f"python -m strands_decider.server --model {self.model_id} --port 8080."
                        )
                    logger.warning("%s", platform_doc)
                    raise StrandsDeciderUnavailableError(platform_doc) from e
                except Exception as e:
                    logger.error("Failed to load local Strands Decider checkpoint '%s': %s", self.model_id, str(e))
                    raise StrandsDeciderError(f"Failed to load local Strands Decider checkpoint: {str(e)}") from e

            engine = await loop.run_in_executor(None, _load)
            _LOCAL_ENGINE_CACHE[cache_key] = engine
            self._local_engine = engine
            return engine

    async def _evaluate_local(self, resp: VulnerabilityResponse) -> DeciderEvaluation:
        """Execute in-process load_engine inference using normalized vulnerability telemetry."""
        engine = await self._get_or_load_local_engine()

        state_text = self.format_evidence_state(resp)
        questions_payload = self.build_systemone_questions()

        loop = asyncio.get_running_loop()

        def _run_inference():
            from strands_decider.schema import ChoiceQuestion, NoulQuestion

            parsed_questions = {
                "priority": ChoiceQuestion(**questions_payload["priority"]),
                "requires_emergency_mitigation": NoulQuestion(
                    **questions_payload["requires_emergency_mitigation"]
                ),
            }
            return engine.ask(state=state_text, questions=parsed_questions)

        try:
            async with _LOCAL_ENGINE_INFERENCE_LOCK:
                raw_result = await asyncio.wait_for(
                    loop.run_in_executor(None, _run_inference),
                    timeout=self.timeout_seconds,
                )

            # Serialize if Pydantic model
            if hasattr(raw_result, "model_dump"):
                data = raw_result.model_dump()
            elif hasattr(raw_result, "dict"):
                data = raw_result.dict()
            else:
                data = raw_result
            return self._parse_decider_response(data)
        except asyncio.TimeoutError as e:
            raise StrandsDeciderTimeoutError(
                f"Local Strands Decider inference timed out after {self.timeout_seconds}s"
            ) from e
        except StrandsDeciderError:
            raise
        except Exception as e:
            raise StrandsDeciderError(f"Local Strands Decider inference failed: {str(e)}") from e

    async def _evaluate_injected(self, resp: VulnerabilityResponse) -> DeciderEvaluation:
        """Handle injected engine or mock callback for deterministic testing."""
        engine = self._injected_engine
        if callable(engine):
            result = engine(resp)
            if asyncio.iscoroutine(result):
                result = await result
            if isinstance(result, DeciderEvaluation):
                return result
            if isinstance(result, dict):
                return self._parse_decider_response(result)

        if hasattr(engine, "ask"):
            state_text = self.format_evidence_state(resp)
            questions_payload = self.build_systemone_questions()
            res = engine.ask(state=state_text, questions=questions_payload)
            if asyncio.iscoroutine(res):
                res = await res
            if hasattr(res, "model_dump"):
                return self._parse_decider_response(res.model_dump())
            elif isinstance(res, dict):
                return self._parse_decider_response(res)

        raise StrandsDeciderValidationError("Injected Strands Decider mock did not produce a valid response.")

    def _parse_decider_response(self, data: Dict[str, Any]) -> DeciderEvaluation:
        """Validate and parse official Strands Decider response payload."""
        answers = data.get("answers", {})
        if not answers or not isinstance(answers, dict):
            raise StrandsDeciderValidationError("Strands Decider response is missing 'answers' dictionary.")

        priority_ans = answers.get("priority", {})
        if not priority_ans:
            raise StrandsDeciderValidationError("Strands Decider response is missing 'priority' answer.")

        raw_choice = str(priority_ans.get("choice", "")).strip().title()
        if raw_choice not in ("Critical", "High", "Medium", "Low"):
            raise StrandsDeciderValidationError(
                f"Strands Decider returned invalid priority choice '{raw_choice}'. Must be Critical, High, Medium, or Low."
            )
        priority = TriagePriority(raw_choice)

        probs = priority_ans.get("probabilities", {})
        if not isinstance(probs, dict) or not probs:
            raise StrandsDeciderValidationError("Strands Decider 'priority' answer is missing probabilities distribution.")

        # Ensure probabilities are floats
        float_probs = {k: float(v) for k, v in probs.items()}

        # Model-derived confidence calculation per official strands_decider derive_confidence formula:
        # (N * p_max - 1) / (N - 1) measuring normalized max-probability distribution concentration
        reported_conf = priority_ans.get("confidence")
        if reported_conf is not None:
            confidence = max(0.0, min(1.0, float(reported_conf)))
        else:
            # Compute directly from probability distribution
            n = len(float_probs)
            if n > 1:
                p_max = max(float_probs.values())
                confidence = max(0.0, min(1.0, (n * p_max - 1.0) / (n - 1.0)))
            else:
                confidence = 1.0

        # Evaluate emergency mitigation Noul answer
        mitigation_ans = answers.get("requires_emergency_mitigation", {})
        if "noul" in mitigation_ans:
            try:
                noul_val = float(mitigation_ans["noul"])
            except (ValueError, TypeError):
                noul_val = 0.0
        elif "probabilities" in mitigation_ans and isinstance(mitigation_ans["probabilities"], dict):
            try:
                noul_val = float(mitigation_ans["probabilities"].get("true", 0.0))
            except (ValueError, TypeError):
                noul_val = 0.0
        else:
            noul_val = 0.0
        requires_emergency = noul_val >= 0.50

        # Checkpoint Provenance:
        # SystemOneResponse.model reports package/implementation identifier (e.g. "strands-decider-0.1.0" or "strands-decider-2B").
        # Configuration checkpoint ID (e.g. "StrandsAgents/strands-decider-2B-qwen3.5-v1-2610") represents the actual trained model weights.
        raw_model = str(data.get("model", "")).strip()
        if not raw_model or raw_model.startswith("strands-decider-"):
            reported_model_id = self.model_id
        else:
            reported_model_id = raw_model

        return DeciderEvaluation(
            priority=priority,
            priority_probabilities=float_probs,
            confidence=round(confidence, 4),
            confidence_is_calibrated=False,
            emergency_mitigation_noul=noul_val,
            requires_emergency_mitigation=requires_emergency,
            model_id=reported_model_id,
            status=ModelInvocationStatus.SUCCESS,
            raw_response=data,
        )


# Global adapter instance
strands_client = StrandsDeciderClient()
