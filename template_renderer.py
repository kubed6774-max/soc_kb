# template_renderer.py

from jinja2 import Template
from models import UseCaseTemplate


class UseCaseRenderer:
    def __init__(self):
        self.template_str = """
# {{ use_case_id }} — {{ use_case_title }}

## I. Use Case Metadata

**1.1 Use Case ID:** {{ use_case_id }}
**1.2 Use Case Title:** {{ use_case_title }}
**1.3 Version:** {{ version }}
**1.4 Status:** {{ status }}
**1.5 Last Updated:** {{ last_updated }}
**1.6 Threat Category:** {{ threat_category }}
**1.7 MITRE ATT&CK Mapping:** {{ mitre_attack_mapping | join(', ') }}
**1.8 Priority / Criticality:** {{ priority }}

## II. Executive Summary & Business Context

**2.1 Business Driver:** {{ business_driver }}
**2.2 Threat Description:** {{ threat_description }}
**2.3 Affected Business Units / Assets:** {{ affected_business_units }}

## III. Threat and Detection Logic

**3.1 Attack Stages Covered:** {{ attack_stages_covered }}
**3.2 Attack Narrative:** {{ attack_narrative }}
**3.3 Threat Indicators (IOCs & Behaviors):** {{ threat_indicators }}
**3.4 Correlation Logic:** {{ correlation_logic }}
**3.5 Behavioral Analytics:** {{ behavioral_analytics }}
**3.6 Threat Intelligence Integration:** {{ threat_intelligence_integration }}

## IV. Log Sources and Data Requirements

**4.1 Required Data Sources:** {{ required_data_sources }}
**4.2 Logging Requirements:** {{ logging_requirements }}
**4.3 Data Onboarding Status:** {{ data_onboarding_status }}

## V. Operational Configuration

**5.1 Infra Domain Grouping:** {{ infra_domain_grouping }}
**5.2 Threat-Driven Grouping:** {{ threat_driven_grouping }}
**5.3 Control-Driven Grouping:** {{ control_driven_grouping }}
**5.4 Alert Severity:** {{ alert_severity }}
**5.5 Estimated Alert Volume:** {{ alert_volume_estimation }}
**5.6 Alert Tuning Baselines:** {{ alert_tuning_baselines }}
**5.7 SOP / Runbook Reference:** {{ sop_reference }}

## VI. Response & Mitigation

**6.1 Initial Response:** {{ initial_response }}
**6.2 Automated Response:** {{ automated_response }}
**6.3 Containment Steps:** {{ containment_steps }}
**6.4 Investigative Steps:** {{ investigative_steps }}
**6.5 Remediation Actions:** {{ remediation_actions }}

## VII. Metrics, Reporting & Dashboards

**7.1 Detection Performance Metrics:** {{ detection_performance_metrics }}
**7.2 Compliance / Audit Reports:** {{ compliance_reports }}
**7.3 Dashboard Visualizations:** {{ dashboard_visualizations }}

## VIII. Governance, Stakeholders & Maintenance

**8.1 Stakeholders:** {{ stakeholders }}
**8.2 Review Cadence:** {{ review_cadence }}
**8.3 Change Log:** {{ change_log }}

## IX. Additional Information

**9.1 Business Impact Score:** {{ business_impact_score }}
**9.2 Automation Maturity Level:** {{ automation_maturity_level }}
**9.3 Cross Use Case Dependencies:** {{ cross_use_case_dependencies }}
**9.4 Additional Notes:** {{ additional_notes }}
"""

    def render_use_case(self, use_case_data: UseCaseTemplate) -> str:
        """Render use case data into Confluence-compatible markup."""
        template = Template(self.template_str)
        data = {k: ("" if v is None else v) for k, v in use_case_data.dict().items()}
        return template.render(**data)

