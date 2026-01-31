# models.py
from pydantic import BaseModel, Field
from typing import List, Optional
from enum import Enum

class ThreatCategory(str, Enum):
    INSIDER_THREAT = "Insider Threat"
    EXTERNAL_ATTACK = "External Attack"
    PRIVILEGE_ABUSE = "Privilege Abuse"
    DATA_EXFILTRATION = "Data Exfiltration"
    MALWARE = "Malware"
    COMPLIANCE_VIOLATION = "Compliance Violation"

class UseCaseTemplate(BaseModel):
    use_case_id: str
    use_case_title: str
    version: str = "v1.0"
    status: str = "Draft"
    last_updated: str
    threat_category: ThreatCategory
    mitre_attack_mapping: List[str] = Field(default_factory=list)
    priority: str = "Medium"

    # Executive Summary
    business_driver: Optional[str] = ""
    threat_description: Optional[str] = ""
    affected_business_units: Optional[str] = ""

    # Threat and Detection Logic
    attack_stages_covered: Optional[str] = ""
    attack_narrative: Optional[str] = ""
    threat_indicators: Optional[str] = ""
    correlation_logic: Optional[str] = ""
    behavioral_analytics: Optional[str] = ""
    threat_intelligence_integration: Optional[str] = "Optional"

    # Log Sources
    required_data_sources: Optional[str] = ""
    logging_requirements: Optional[str] = ""
    data_onboarding_status: Optional[str] = "Pending"

    # Operational Procedures
    infra_domain_grouping: Optional[str] = ""
    threat_driven_grouping: Optional[str] = ""
    control_driven_grouping: Optional[str] = ""
    alert_severity: Optional[str] = "Medium"
    alert_volume_estimation: Optional[str] = "Unknown"
    alert_tuning_baselines: Optional[str] = ""
    sop_reference: Optional[str] = ""

    # Response & Mitigation
    initial_response: Optional[str] = ""
    automated_response: Optional[str] = ""
    containment_steps: Optional[str] = ""
    investigative_steps: Optional[str] = ""
    remediation_actions: Optional[str] = ""

    # Metrics and Reporting
    detection_performance_metrics: Optional[str] = ""
    compliance_reports: Optional[str] = ""
    dashboard_visualizations: Optional[str] = ""

    # Review and Maintenance
    stakeholders: Optional[str] = ""
    review_cadence: Optional[str] = "Quarterly"
    change_log: Optional[str] = ""

    # Optional Enhancements
    business_impact_score: Optional[str] = "Unknown"
    automation_maturity_level: Optional[str] = "Unknown"
    cross_use_case_dependencies: Optional[str] = ""
    additional_notes: Optional[str] = ""
