# llm_generator.py

import json
import asyncio
import re
from typing import Dict, Any, List, Optional

from loguru import logger
from langchain_ollama import OllamaLLM

from config import settings


class UseCaseGenerator:
    """
    Wraps Ollama LLM and returns validated JSON dictionaries for use cases.
    """

    DEFAULT_FIELDS: Dict[str, Any] = {
        "business_driver": "",
        "threat_description": "",
        "affected_business_units": "IT, Security",
        "attack_stages_covered": "Initial Access, Execution",
        "attack_narrative": "",
        "threat_indicators": "",
        "correlation_logic": "",
        "behavioral_analytics": "",
        "threat_intelligence_integration": "Optional",
        "required_data_sources": "SIEM, EDR",
        "logging_requirements": "",
        "data_onboarding_status": "Pending",
        "infra_domain_grouping": "",
        "threat_driven_grouping": "",
        "control_driven_grouping": "",
        "alert_severity": "Medium",
        "alert_volume_estimation": "Unknown",
        "alert_tuning_baselines": "",
        "sop_reference": "",
        "initial_response": "",
        "automated_response": "",
        "containment_steps": "Isolate systems",
        "investigative_steps": "Review logs",
        "remediation_actions": "Patch systems",
        "detection_performance_metrics": "FPR, MTTD",
        "compliance_reports": "",
        "dashboard_visualizations": "",
        "stakeholders": "SOC, IT",
        "review_cadence": "Quarterly",
        "change_log": "",
        "business_impact_score": "Unknown",
        "automation_maturity_level": "Unknown",
        "cross_use_case_dependencies": "",
        "additional_notes": "",
        "mitre_attack_mapping": ["T1078"],
    }

    def __init__(
        self,
        model_name: Optional[str] = None,
        base_url: Optional[str] = None,
        num_predict: Optional[int] = None,
        temperature: float = 0.3,
    ) -> None:
        self.model_name = model_name or settings.OLLAMA_MODEL_NAME
        self.base_url = base_url or settings.OLLAMA_BASE_URL
        self.num_predict = num_predict or settings.OLLAMA_NUM_PREDICT

        try:
            self.llm = OllamaLLM(
                model=self.model_name,
                base_url=self.base_url,
                temperature=temperature,
                num_predict=self.num_predict,
            )
            logger.info(
                f"Ollama LLM initialized (model={self.model_name}, url={self.base_url}, num_predict={self.num_predict})"
            )
        except Exception as e:
            logger.error(f"Failed to initialize Ollama LLM: {e}")
            self.llm = None

        self.prompt_template_str = """
You are a SOC detection engineer.

Generate a single JSON object (no explanations, no markdown) describing a security use case.

Input:
- Use case title: "{use_case_title}"
- Threat category: "{threat_category}"

Required JSON keys (strings unless noted):
- business_driver
- threat_description
- affected_business_units
- attack_stages_covered
- attack_narrative
- threat_indicators
- correlation_logic
- behavioral_analytics
- threat_intelligence_integration
- required_data_sources
- logging_requirements
- data_onboarding_status
- infra_domain_grouping
- threat_driven_grouping
- control_driven_grouping
- alert_severity
- alert_volume_estimation
- alert_tuning_baselines
- sop_reference
- initial_response
- automated_response
- containment_steps
- investigative_steps
- remediation_actions
- detection_performance_metrics
- compliance_reports
- dashboard_visualizations
- stakeholders
- review_cadence
- change_log
- business_impact_score
- automation_maturity_level
- cross_use_case_dependencies
- additional_notes
- mitre_attack_mapping (array of strings, e.g. ["T1078", "T1059"])

Rules:
- Output valid JSON only.
- Do not include code fences or comments.
"""

    async def generate_use_case_content(
        self,
        use_case_title: str,
        threat_category: str,
        attempts: int = 3,
        backoff: float = 2.0,
    ) -> Dict[str, Any]:
        prompt = self.prompt_template_str.format(
            use_case_title=use_case_title,
            threat_category=threat_category,
        )

        for attempt in range(1, attempts + 1):
            try:
                if self.llm is None:
                    raise RuntimeError("LLM client not initialized")

                response = await asyncio.to_thread(self.llm.invoke, prompt)
                if not isinstance(response, str):
                    raise ValueError("LLM response is not a string")

                content = self._extract_json_from_text(response)
                content = self._fix_llm_validation_errors(content)
                content = self._ensure_required_keys(content)

                logger.info(f"LLM generation succeeded for '{use_case_title}'")
                return content
            except (json.JSONDecodeError, ValueError) as e:
                logger.warning(
                    f"Validation/JSON error in attempt {attempt} for '{use_case_title}': {e}"
                )
            except Exception as e:
                logger.warning(
                    f"System/LLM error in attempt {attempt} for '{use_case_title}': {e}"
                )

            if attempt < attempts:
                await asyncio.sleep(backoff * attempt)

        logger.error(
            f"LLM generation failed after {attempts} attempts for '{use_case_title}'. Using fallback."
        )
        return self._get_fallback_content(use_case_title, threat_category)

    # ----------------- Normalization helpers -----------------

    def _fix_llm_validation_errors(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        fixes = {
            "mitre_attack_mapping": self._flatten_mitre_mapping,
            "affected_business_units": self._list_to_string,
            "attack_stages_covered": self._list_to_string,
            "threat_indicators": self._list_to_string,
            "required_data_sources": self._list_to_string,
            "containment_steps": self._list_to_string,
            "investigative_steps": self._list_to_string,
            "remediation_actions": self._list_to_string,
            "detection_performance_metrics": self._list_to_string,
            "stakeholders": self._list_to_string,
            "cross_use_case_dependencies": self._list_to_string,
        }

        for field, fixer in fixes.items():
            if field in raw_data:
                raw_data[field] = fixer(raw_data[field])
        return raw_data

    def _list_to_string(self, value: Any) -> str:
        if isinstance(value, list):
            return ", ".join(str(x).strip() for x in value if x)
        return str(value).strip()

    def _flatten_mitre_mapping(self, mapping: Any) -> List[str]:
        if isinstance(mapping, dict):
            return [
                f"{k}: {', '.join(str(v).strip() for v in (v if isinstance(v, list) else [v]))}"
                for k, v in mapping.items()
            ]
        if isinstance(mapping, list):
            return [str(x).strip() for x in mapping if x]
        return [str(mapping)] if mapping else []
        
        
            # ----------------- JSON extraction -----------------

    def _extract_json_from_text(self, text: str) -> Dict[str, Any]:
        """
        Extract JSON from the LLM text output by balancing braces.
        """
        # Remove code fences/backticks safely
        clean_text = text.replace("```", "").replace("`", "")

        start = clean_text.find("{")
        

        if start == -1:
            raise ValueError("No JSON object found in LLM response")

        stack: List[str] = []
        end: Optional[int] = None
        for i, ch in enumerate(clean_text[start:], start=start):
            if ch == "{":
                stack.append("{")
            elif ch == "}":
                if stack:
                    stack.pop()
                if not stack:
                    end = i
                    break

        if end is None:
            raise ValueError("Malformed JSON: closing brace not found")

        json_str = clean_text[start : end + 1]
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            fixed = json_str.replace("'", '"')
            fixed = re.sub(r",\s*([}\]])", r"\1", fixed)
            return json.loads(fixed)

        
    
    # ----------------- Defaults & fallback -----------------

    def _ensure_required_keys(self, content: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(self.DEFAULT_FIELDS)
        merged.update(content or {})
        return merged

    def _get_fallback_content(
        self, use_case_title: str, threat_category: str
    ) -> Dict[str, Any]:
        fallback = dict(self.DEFAULT_FIELDS)
        fallback.update(
            {
                "business_driver": f"Detect and respond to {use_case_title}",
                "threat_description": f"{threat_category} threat related to {use_case_title}",
                "attack_narrative": f"Threat actor performs {use_case_title} activities",
                "threat_indicators": "Behavioral anomalies, IOC matches",
                "containment_steps": "Isolate; Block",
                "investigative_steps": "Logs; Forensics",
                "remediation_actions": "Patch; Harden",
                "alert_severity": "High",
                "business_impact_score": "High",
                "automation_maturity_level": "Medium",
            }
        )
        return fallback

