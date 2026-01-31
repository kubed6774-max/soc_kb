# main.py

import asyncio
import argparse
from datetime import datetime
from typing import List, Optional

import pandas as pd
from loguru import logger

from config import settings
from models import UseCaseTemplate, ThreatCategory
from llm_generator import UseCaseGenerator
from template_renderer import UseCaseRenderer
from confluence_manager import ConfluenceManager


CATEGORY_MAP = {
    "insider": ThreatCategory.INSIDER_THREAT,
    "external": ThreatCategory.EXTERNAL_ATTACK,
    "privilege": ThreatCategory.PRIVILEGE_ABUSE,
    "data": ThreatCategory.DATA_EXFILTRATION,
    "malware": ThreatCategory.MALWARE,
    "compliance": ThreatCategory.COMPLIANCE_VIOLATION,
}


class UseCaseWorkflow:
    def __init__(self, concurrency: Optional[int] = None, dry_run: bool = False) -> None:
        if concurrency is None:
            concurrency = settings.DEFAULT_CONCURRENCY

        self.llm_generator = UseCaseGenerator(base_url=settings.OLLAMA_BASE_URL)
        self.template_renderer = UseCaseRenderer()
        
        self.confluence_manager = ConfluenceManager(
            url=settings.CONFLUENCE_URL,
            username=settings.CONFLUENCE_USERNAME,
            apitoken=settings.CONFLUENCE_API_TOKEN,
            space=settings.CONFLUENCE_SPACE,
            dryrun=dry_run,
        )
        
        self.semaphore = asyncio.Semaphore(concurrency)

        logger.info(
            f"UseCaseWorkflow initialized (concurrency={concurrency}, dry_run={dry_run})"
        )

    def load_use_case_titles(self, csv_file: str) -> pd.DataFrame:
        df = pd.read_csv(csv_file)
        required_columns = ["title", "threat_category", "use_case_id"]
        if not all(col in df.columns for col in required_columns):
            raise ValueError(f"CSV must contain columns: {required_columns}")
        return df

    def map_threat_category(self, category_str: str) -> ThreatCategory:
        value = (category_str or "").lower()
        for key, enum_val in CATEGORY_MAP.items():
            if key in value:
                return enum_val
        return ThreatCategory.INSIDER_THREAT

    async def process_single_use_case(self, row: pd.Series) -> Optional[UseCaseTemplate]:
        async with self.semaphore:
            title = row["title"]
            threat_cat_raw = row["threat_category"]
            use_case_id = str(row["use_case_id"])

            try:
                content = await self.llm_generator.generate_use_case_content(
                    use_case_title=title,
                    threat_category=threat_cat_raw,
                )

                # Convert all LLM values to strings for Pydantic
                def to_str(value):
                    if value is None:
                        return ""
                    if isinstance(value, (bool, int, float)):
                        return str(value)
                    if isinstance(value, (dict, list)):
                        return str(value)
                    return str(value)

                content_str = {k: to_str(v) for k, v in content.items()}

                # Parse mitre_attack_mapping as list
                mitre_mapping = []
                mitre_str = content_str.get("mitre_attack_mapping", "")
                if mitre_str:
                    mitre_mapping = [x.strip() for x in mitre_str.split(",") if x.strip()]

                uc = UseCaseTemplate(
                    use_case_id=use_case_id,
                    use_case_title=title,
                    last_updated=datetime.now().strftime("%Y-%m-%d"),
                    threat_category=self.map_threat_category(threat_cat_raw),
                    mitre_attack_mapping=mitre_mapping,
                    priority=content_str.get("alert_severity", "Medium"),
                    business_driver=content_str.get("business_driver"),
                    threat_description=content_str.get("threat_description"),
                    affected_business_units=content_str.get("affected_business_units"),
                    attack_stages_covered=content_str.get("attack_stages_covered"),
                    attack_narrative=content_str.get("attack_narrative"),
                    threat_indicators=content_str.get("threat_indicators"),
                    correlation_logic=content_str.get("correlation_logic"),
                    behavioral_analytics=content_str.get("behavioral_analytics"),
                    threat_intelligence_integration=content_str.get("threat_intelligence_integration", "Optional"),
                    required_data_sources=content_str.get("required_data_sources"),
                    logging_requirements=content_str.get("logging_requirements"),
                    data_onboarding_status=content_str.get("data_onboarding_status", "Pending"),
                    infra_domain_grouping=content_str.get("infra_domain_grouping"),
                    threat_driven_grouping=content_str.get("threat_driven_grouping"),
                    control_driven_grouping=content_str.get("control_driven_grouping"),
                    alert_severity=content_str.get("alert_severity", "Medium"),
                    alert_volume_estimation=content_str.get("alert_volume_estimation", "Unknown"),
                    alert_tuning_baselines=content_str.get("alert_tuning_baselines"),
                    sop_reference=content_str.get("sop_reference"),
                    initial_response=content_str.get("initial_response"),
                    automated_response=content_str.get("automated_response"),
                    containment_steps=content_str.get("containment_steps"),
                    investigative_steps=content_str.get("investigative_steps"),
                    remediation_actions=content_str.get("remediation_actions"),
                    detection_performance_metrics=content_str.get("detection_performance_metrics"),
                    compliance_reports=content_str.get("compliance_reports"),
                    dashboard_visualizations=content_str.get("dashboard_visualizations"),
                    stakeholders=content_str.get("stakeholders"),
                    review_cadence=content_str.get("review_cadence", "Quarterly"),
                    change_log=content_str.get("change_log"),
                    business_impact_score=content_str.get("business_impact_score", "Unknown"),
                    automation_maturity_level=content_str.get("automation_maturity_level", "Unknown"),
                    cross_use_case_dependencies=content_str.get("cross_use_case_dependencies"),
                    additional_notes=content_str.get("additional_notes"),
                )

                logger.info(f"Successfully processed use case: {title}")
                return uc
            except Exception as e:
                logger.error(f"Error processing use case '{title}': {e}")
                return None

    async def process_batch_use_cases(
        self, df: pd.DataFrame, batch_size: int
    ) -> List[UseCaseTemplate]:
        all_use_cases: List[UseCaseTemplate] = []
        rows = [row for _, row in df.iterrows()]

        total = len(rows)
        logger.info(f"Processing {total} use cases (batch_size={batch_size})")

        for i in range(0, total, batch_size):
            batch = rows[i : i + batch_size]
            logger.info(f"Starting batch {i // batch_size + 1} ({len(batch)} items)")

            tasks = [self.process_single_use_case(row) for row in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for res in results:
                if isinstance(res, UseCaseTemplate):
                    all_use_cases.append(res)
                elif isinstance(res, Exception):
                    logger.error(f"Unhandled exception in batch: {res}")

            if settings.ENABLE_BATCH_SLEEP and settings.BATCH_SLEEP_SECONDS > 0:
                await asyncio.sleep(settings.BATCH_SLEEP_SECONDS)

        logger.info(f"Finished generation; valid use cases: {len(all_use_cases)}")
        return all_use_cases

    def upload_to_confluence(self, use_cases: List[UseCaseTemplate]) -> None:
        success = 0
        total = len(use_cases)
        logger.info(f"Uploading {total} use cases to Confluence")

        for uc in use_cases:
            try:
                content = self.template_renderer.render_use_case(uc)
                title = f"{uc.use_case_id} — {uc.use_case_title}"
                ok = self.confluence_manager.create_or_update_page(
                    title=title, content=content
                )
                if ok:
                    success += 1
            except Exception as e:
                logger.error(f"Upload failed for {uc.use_case_title}: {e}")

        logger.info(f"Uploaded {success}/{total} use cases")

    async def run_workflow(self, input_csv: str, batch_size: int) -> None:
        logger.info("Starting workflow")
        df = self.load_use_case_titles(input_csv)
        use_cases = await self.process_batch_use_cases(df, batch_size=batch_size)
        self.upload_to_confluence(use_cases)
        logger.info("Workflow finished")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Use Case Generation Workflow")
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        help="CSV file with columns title, threat_category, use_case_id",
    )
    parser.add_argument(
        "--batch",
        "-b",
        type=int,
        default=settings.DEFAULT_BATCH_SIZE,
        help="Batch size for LLM calls",
    )
    parser.add_argument(
        "--concurrency",
        "-c",
        type=int,
        default=settings.DEFAULT_CONCURRENCY,
        help="Max concurrency",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Don't call Confluence; only generate"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    workflow = UseCaseWorkflow(concurrency=args.concurrency, dry_run=args.dry_run)
    asyncio.run(workflow.run_workflow(args.input, batch_size=args.batch))

