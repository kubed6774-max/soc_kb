# test_confluence.py

from config import settings
from confluence_manager import ConfluenceManager
from loguru import logger

def main():
    logger.info("Testing Confluence connectivity...")
    cm = ConfluenceManager(
        url=settings.CONFLUENCE_URL,
        username=settings.CONFLUENCE_USERNAME,
        apitoken=settings.CONFLUENCE_API_TOKEN,
        space=settings.CONFLUENCE_SPACE,
        dryrun=False,
    )
    stats = cm.get_space_stats()
    logger.info(f"Space stats: {stats}")

if __name__ == "__main__":
    main()

