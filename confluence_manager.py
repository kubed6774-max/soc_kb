from typing import Optional, Dict, Any
from atlassian import Confluence
from loguru import logger

class ConfluenceManager:
    def __init__(self, url: str, username: str, apitoken: str, space: str, dryrun: bool = False):
        self.dryrun = dryrun
        if not dryrun:
            self.confluence = Confluence(
                url=url,
                username=username,
                password=apitoken,
                cloud=True,
            )
        else:
            self.confluence = None
        self.space = space

    def extract_page_id(self, page_response: Any) -> Optional[str]:
        """Extract page id from various response shapes."""
        if not page_response:
            return None
        if isinstance(page_response, dict):
            if 'id' in page_response:
                return str(page_response['id'])
            if 'results' in page_response and isinstance(page_response['results'], list) and page_response['results']:
                item = page_response['results'][0]
                return str(item.get('id') or item.get('pageId') or item.get('id'))
        try:
            if hasattr(page_response, 'get'):
                return str(page_response.get('id'))
        except Exception:
            pass
        return None

    def get_page_by_title(self, title: str) -> Optional[Dict[str, Any]]:
        """Wrapper to get page by title and return normalized dict or None."""
        if self.dryrun:
            logger.debug(f"dryrun: get_page_by_title {title}")
            return None

        try:
            page = self.confluence.get_page_by_title(
                space=self.space,
                title=title,
            )
            if not page:
                return None
            return page
        except Exception as e:
            logger.warning(f"Error fetching page by title {title}: {e}")
            return None

    def create_or_update_page(self, title: str, content: str, parent_id: Optional[str] = None) -> bool:
        """Create or update a Confluence page. Returns True on success."""
        try:
            if self.dryrun:
                logger.info(f"dryrun: Would create/update page '{title}' in space '{self.space}'")
                return True

            existing_page = self.get_page_by_title(title)
            page_id = self.extract_page_id(existing_page)

            if existing_page and page_id:
                logger.info(f"Updating existing page '{title}'")
                self.confluence.update_page(
                    page_id=page_id,
                    title=title,
                    body=content,
                )
                logger.info(f"Updated page '{title}'")
            else:
                logger.info(f"Creating new page '{title}'")
                self.confluence.create_page(
                    space=self.space,
                    title=title,
                    body=content,
                    parent_id=parent_id,
                    type='page',
                )
                logger.info(f"Created page '{title}'")
            return True
        except Exception as e:
            logger.error(f"Error creating/updating page '{title}': {e}")
            return False

    def create_use_case_structure(self) -> Optional[str]:
        """Create default directory structure. Returns id of main page or None."""
        try:
            if self.dryrun:
                logger.info("dryrun: create_use_case_structure")
                return None

            main_title = "SOC Use Cases"
            existing = self.get_page_by_title(main_title)
            if existing:
                return self.extract_page_id(existing)

            main_page = self.confluence.create_page(
                space=self.space,
                title=main_title,
                body="Comprehensive Security Use Case Library",
                type='page',
            )
            return self.extract_page_id(main_page)
        except Exception as e:
            logger.error(f"Error creating use case structure: {e}")
            return None

    def get_space_stats(self, status_filter: str = "current") -> Dict[str, int]:
        """Fetch page count by status in the space."""
        if self.dryrun:
            return {"total": 0, "active": 0}

        try:
            # CQL for space pages
            cql = f'space="{self.space}" and type=page'
            if status_filter == "current":
                cql += ' and status="current"'
            
            response = self.confluence.cql(cql)
            total = response.get("totalSize", 0)
            
            return {
                "total": total,
                "active": total if status_filter == "current" else 0
            }
        except Exception as e:
            logger.error(f"Stats fetch error: {e}")
            return {"total": 0, "active": 0}

    def get_use_case_stats(self) -> Dict[str, Any]:
        """Get detailed stats for UC- prefixed pages."""
        if self.dryrun:
            return {"uc_total": 0, "uc_active": 0, "threat_categories": {}}

        try:
            # Get UC- prefixed pages
            cql_active = f'space="{self.space}" and type=page and title ~ "UC-*" and status="current"'
            cql_total = f'space="{self.space}" and type=page and title ~ "UC-*"' 
            
            active_pages = self.confluence.cql(cql_active)
            total_pages = self.confluence.cql(cql_total)
            
            # Simple threat category count from titles (e.g., UC-001 — Insider Threat)
            categories = {}
            for page in active_pages.get("results", []):
                title = page.get("title", "")
                if " — " in title:
                    category = title.split(" — ")[-1].split()[0]  # First word after "—"
                    categories[category] = categories.get(category, 0) + 1
            
            return {
                "uc_total": total_pages.get("totalSize", 0),
                "uc_active": active_pages.get("totalSize", 0),
                "threat_categories": categories
            }
        except Exception as e:
            logger.error(f"Use case stats error: {e}")
            return {"uc_total": 0, "uc_active": 0, "threat_categories": {}}
