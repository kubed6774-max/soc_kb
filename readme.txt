Requirements 
============
pydantic==1.10.12
pandas==2.2.0
loguru==0.7.2
tqdm==4.66.1
jinja2==3.1.2
atlassian-python-api==3.41.9
langchain==0.1.0
requests==2.31.0
python-dotenv==1.0.1
ollama

pip install fastapi uvicorn python-multipart jinja2

------------------------
High-level architecture (what will change)  for Browser GUI 
Browser (GUI)
   |
   | HTTP (localhost:8000)
   v
FastAPI app (new)
   |
   | calls
   v
UseCaseWorkflow (your existing code)
   |
   v
Ollama LLM  →  Confluence

----------------------------------

Why FastAPI?
Native async support (matches your code perfectly)
Automatic web server
Easy HTML + REST
Production-ready
Much cleaner than Flask for async workflows

--------------------
