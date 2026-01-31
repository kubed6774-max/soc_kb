# web_app.py

import os
import shutil
import asyncio
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, BackgroundTasks, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from loguru import logger

from main import UseCaseWorkflow
from config import settings

app = FastAPI(title="SOC Use Case Uploader")

# Static files (for logo)
STATIC_DIR = Path("static")
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# -----------------------------
# Simple HTML UI (Mizuho-style)
# -----------------------------

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>SOC Use Case Uploader</title>
    <style>
        body { margin: 0; font-family: Arial, sans-serif; background-color: #f5f5f8; }
        .top-bar {
            background-color: #002b79; /* deep Mizuho blue */
            color: white;
            padding: 10px 30px;
            display: flex;
            align-items: center;
        }
        .top-bar img.logo {
            height: 40px;
            margin-right: 20px;
        }
        .top-bar-title {
            font-size: 20px;
            font-weight: 600;
        }
        .accent-bar {
            height: 4px;
            background-color: #e60028; /* Mizuho red accent */
        }
        .page-container {
            max-width: 900px;
            margin: 30px auto;
            padding: 0 20px 40px 20px;
        }
        h1 { margin-bottom: 0.4em; color: #002b79; }
        .card {
            border: 1px solid #ddd;
            padding: 24px;
            border-radius: 8px;
            background-color: #ffffff;
            box-shadow: 0 1px 3px rgba(0,0,0,0.06);
        }
        label { display: block; margin-top: 12px; font-weight: bold; color: #002b79; }
        input[type="file"],
        input[type="number"] {
            width: 100%;
            padding: 6px;
            margin-top: 4px;
            box-sizing: border-box;
        }
        button {
            margin-top: 18px;
            padding: 10px 18px;
            font-size: 14px;
            background-color: #002b79;
            color: #ffffff;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background-color: #001c4f;
        }
        .note { margin-top: 16px; color: #555; font-size: 13px; }
        .warning { color: #b00; font-weight: bold; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="top-bar">
        <img src="/static/mizuho-logo.png" alt="Mizuho" class="logo" />
        <div class="top-bar-title">SOC Use Case Generator</div>
    </div>
    <div class="accent-bar"></div>

    <div class="page-container">
        <h1>Upload Use Case CSV</h1>
        <div class="card">
            <p class="warning">Make sure Ollama is running on <strong>localhost:11434</strong> and Confluence settings are correct.</p>

            <form action="/upload" method="post" enctype="multipart/form-data">
                <label for="file">CSV file (title, threat_category, use_case_id)</label>
                <input type="file" id="file" name="file" accept=".csv" required />

                <label for="batch">Batch size</label>
                <input type="number" id="batch" name="batch" value="5" min="1" max="100" />

                <label for="concurrency">Concurrency</label>
                <input type="number" id="concurrency" name="concurrency" value="5" min="1" max="50" />

                <label>
                    <input type="checkbox" name="dry_run" value="1" />
                    Dry run (generate only, do not upload to Confluence)
                </label>

                <button type="submit">Start Generation</button>
            </form>

            <p class="note">
                After you submit, generation and uploads run in the background.
                Check your Confluence space for new pages under "SOC Use Cases" and your server logs for progress.
            </p>
        </div>
    </div>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML_PAGE


async def _run_workflow_background(
    csv_path: Path, batch_size: int, concurrency: int, dry_run: bool
):
    logger.info(
        f"Background job started: csv={csv_path}, batch={batch_size}, concurrency={concurrency}, dry_run={dry_run}"
    )
    try:
        workflow = UseCaseWorkflow(concurrency=concurrency, dry_run=dry_run)
        await workflow.run_workflow(str(csv_path), batch_size=batch_size)
        logger.info("Background job completed")
    except Exception as e:
        logger.error(f"Background workflow error: {e}")
    finally:
        try:
            csv_path.unlink(missing_ok=True)
        except Exception as e:
            logger.warning(f"Failed to delete temp CSV '{csv_path}': {e}")


@app.post("/upload", response_class=HTMLResponse)
async def upload_use_cases(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    batch: int = Form(5),
    concurrency: int = Form(5),
    dry_run: str | None = Form(None),
):
    if file.content_type not in ("text/csv", "application/vnd.ms-excel"):
        return HTMLResponse(
            content="<h3>Invalid file type. Please upload a CSV file.</h3>",
            status_code=400,
        )

    temp_path = UPLOAD_DIR / file.filename
    try:
        with temp_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        logger.error(f"Error saving uploaded file: {e}")
        return HTMLResponse(
            content=f"<h3>Error saving file: {e}</h3>",
            status_code=500,
        )

    is_dry_run = dry_run == "1"

    background_tasks.add_task(
        _run_workflow_background,
        csv_path=temp_path,
        batch_size=batch,
        concurrency=concurrency,
        dry_run=is_dry_run,
    )

    return HTMLResponse(
        content=f"""
        <h2>Job started</h2>
        <p>File: {file.filename}</p>
        <p>Batch size: {batch}</p>
        <p>Concurrency: {concurrency}</p>
        <p>Dry run: {"Yes" if is_dry_run else "No"}</p>
        <p>Generation is running in the background. You can close this tab.</p>
        <p><a href="/">Go Back</a></p>
        """,
        status_code=200,
    )

