"""
SOC Dashboard with enhanced features and database integration
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import tempfile
import sqlite3
from datetime import datetime
import re
import os
import logging
import asyncio
import time
import uuid
import hashlib
import numpy as np
from typing import List, Dict, Any, Optional

# Import existing components
try:
    from main import UseCaseWorkflow
    from config import settings
    from confluence_manager import ConfluenceManager
    from llm_generator import UseCaseGenerator
    from database import db_instance  # Import database instance
except ImportError as e:
    st.error(f"Import error: {e}")
    # Create dummy classes for missing imports
    class UseCaseWorkflow:
        def __init__(self, *args, **kwargs):
            pass
        async def run_workflow(self, *args, **kwargs):
            pass
    class Settings:
        CONFLUENCE_SPACE = "SOCTEST"
        OLLAMA_BASE_URL = "http://localhost:11434"
        OLLAMA_MODEL_NAME = "mistral:7b-instruct-v0.2-q4_K_M"
        DEFAULT_BATCH_SIZE = 5
        DEFAULT_CONCURRENCY = 5
    settings = Settings()
    db_instance = None

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# Page configuration
st.set_page_config(
    page_title="SOC Dashboard",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session states
if 'session_id' not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []
if 'uploaded_logs' not in st.session_state:
    st.session_state.uploaded_logs = None
if 'query_results' not in st.session_state:
    st.session_state.query_results = None
if 'confluence_stats' not in st.session_state:
    st.session_state.confluence_stats = None
if 'selected_query' not in st.session_state:
    st.session_state.selected_query = None

# Initialize database chat history
if db_instance:
    try:
        if not st.session_state.chat_history:
            db_history = db_instance.get_chat_history(
                st.session_state.session_id, 
                limit=50
            )
            st.session_state.chat_history = db_history
    except Exception as e:
        logger.warning(f"Could not load chat history from database: {e}")

# ====================
# SIDEBAR NAVIGATION
# ====================

st.sidebar.title("🔒 SOC Dashboard")
st.sidebar.markdown("---")

# Navigation menu
page_options = [
    "🏠 Home - Use Case Generator",
    "📊 Use Case Metrics Dashboard", 
    "🔍 Detection Rule Queries",
    "🤖 Incident Response Bot",
    "📈 Analytics Dashboard"
]

page = st.sidebar.radio("Navigation", page_options)

st.sidebar.markdown("---")
st.sidebar.markdown("### 🔧 Configuration")
st.sidebar.info(f"**Confluence Space:** {settings.CONFLUENCE_SPACE}")
st.sidebar.info(f"**Ollama URL:** {settings.OLLAMA_BASE_URL}")

# Database stats in sidebar
if db_instance:
    try:
        db_stats = db_instance.get_query_analytics(days=7)
        st.sidebar.markdown("### 📊 Database Stats")
        col1, col2 = st.columns(2)
        with col1:
            queries = db_instance.get_all_queries()
            st.sidebar.metric("Saved Queries", len(queries))
        with col2:
            success_rate = db_stats.get('success_stats', {}).get('success_rate', 0)
            st.sidebar.metric("Query Success", f"{success_rate:.1f}%")
    except Exception as e:
        logger.warning(f"Could not load database stats: {e}")

# ====================
# HELPER FUNCTIONS
# ====================

def hash_query(query: str) -> str:
    """Generate hash for query caching."""
    return hashlib.md5(query.encode()).hexdigest()

def run_async(coro):
    """
    Helper to run an async coroutine from Streamlit (which is sync).
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)

# ====================
# PAGE 1: HOME - USE CASE GENERATOR
# ====================

if page == "🏠 Home - Use Case Generator":
    st.title("SOC Use Case Generator & Confluence Uploader")

    st.markdown(
        """
        Upload a CSV with columns **title**, **threat_category**, **use_case_id**.
        The app will generate detailed use cases via Ollama and upload them to Confluence
        using the configured credentials and space.
        """
    )

    with st.expander("Current Confluence & LLM settings", expanded=False):
        col1, col2 = st.columns(2)
        with col1:
            st.write(f"**Confluence URL:** `{settings.CONFLUENCE_URL}`")
            st.write(f"**Confluence Space:** `{settings.CONFLUENCE_SPACE}`")
        with col2:
            st.write(f"**Ollama URL:** `{settings.OLLAMA_BASE_URL}`")
            st.write(f"**Model:** `{settings.OLLAMA_MODEL_NAME}`")

    uploaded_file = st.file_uploader(
        "Upload Use Case CSV",
        type=["csv"],
        help="CSV must contain columns: title, threat_category, use_case_id",
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        batch_size = st.number_input(
            "Batch size",
            min_value=1,
            max_value=50,
            value=settings.DEFAULT_BATCH_SIZE,
            step=1,
        )
    with col2:
        concurrency = st.number_input(
            "Concurrency",
            min_value=1,
            max_value=20,
            value=settings.DEFAULT_CONCURRENCY,
            step=1,
        )
    with col3:
        dry_run = st.checkbox(
            "Dry run (do not upload to Confluence)", 
            value=False,
            help="If enabled, pages will NOT be created/updated in Confluence."
        )

    if uploaded_file is not None:
        st.subheader("📋 Preview of uploaded CSV")
        try:
            df_preview = pd.read_csv(uploaded_file)
            st.dataframe(df_preview.head(), use_container_width=True)
            
            # Show summary stats
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Use Cases", len(df_preview))
            with col2:
                if 'threat_category' in df_preview.columns:
                    st.metric("Unique Categories", df_preview['threat_category'].nunique())
                else:
                    st.metric("Columns", len(df_preview.columns))
            with col3:
                if 'use_case_id' in df_preview.columns:
                    st.metric("Use Case IDs", df_preview['use_case_id'].nunique())
                else:
                    st.metric("Rows", len(df_preview))
                
        except Exception as e:
            st.error(f"Failed to read CSV: {e}")
            st.stop()

    if st.button("🚀 Generate & Upload Use Cases", 
                 type="primary", 
                 disabled=uploaded_file is None,
                 use_container_width=True):
        
        if uploaded_file is None:
            st.warning("Please upload a CSV first.")
            st.stop()

        # Save uploaded CSV to a temporary file
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
                tmp.write(uploaded_file.getvalue())
                tmp_path = tmp.name
        except Exception as e:
            st.error(f"Failed to persist uploaded CSV: {e}")
            st.stop()

        with st.spinner("Starting generation and upload workflow. This may take a few minutes..."):
            try:
                workflow = UseCaseWorkflow(concurrency=int(concurrency), 
                                         dry_run=bool(dry_run))

                # Run the async workflow
                run_async(workflow.run_workflow(tmp_path, batch_size=int(batch_size)))

                # Success message
                if dry_run:
                    st.success("✅ Use cases generated in memory (dry run). No Confluence upload attempted.")
                else:
                    st.success("✅ Use cases generated and uploaded to Confluence successfully!")
                    st.balloons()
                    
            except Exception as e:
                logger.exception("Error during workflow execution")
                st.error(f"❌ Workflow failed: {e}")
            finally:
                # Clean up temp file
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

# ====================
# PAGE 2: USE CASE METRICS DASHBOARD
# ====================

elif page == "📊 Use Case Metrics Dashboard":
    st.title("📊 Use Case Metrics Dashboard")
    
    # Fetch Confluence stats with caching
    @st.cache_data(ttl=300)  # Cache for 5 minutes
    def fetch_confluence_stats():
        try:
            # Try to get from database cache first
            cache_key = f"confluence_stats_{settings.CONFLUENCE_SPACE}"
            cached = None
            if db_instance:
                cached = db_instance.get_cached_metrics(cache_key)
            
            if cached:
                logger.info("Using cached Confluence data")
                return cached
            
            # Fetch from Confluence
            cm = ConfluenceManager(
                url=settings.CONFLUENCE_URL,
                username=settings.CONFLUENCE_USERNAME,
                apitoken=settings.CONFLUENCE_API_TOKEN,
                space=settings.CONFLUENCE_SPACE,
                dryrun=False,
            )
            stats = cm.get_use_case_stats()
            
            # Cache in database
            if db_instance:
                db_instance.cache_metrics(cache_key, stats, ttl_minutes=5)
                logger.info("Updated Confluence cache")
            
            return stats
        except Exception as e:
            st.error(f"Failed to fetch Confluence stats: {e}")
            return None
    
    # Refresh button
    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("🔄 Refresh Data", use_container_width=True):
            st.cache_data.clear()
            # Clear specific cache key
            cache_key = f"confluence_stats_{settings.CONFLUENCE_SPACE}"
            if db_instance:
                db_instance.cache_metrics(cache_key, {}, ttl_minutes=0)  # Immediate expiry
            st.rerun()
    
    # Fetch and display stats
    with st.spinner("Fetching Confluence data..."):
        stats = fetch_confluence_stats()
    
    if stats:
        # KPI Cards
        st.subheader("📈 Key Performance Indicators")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Use Cases", stats.get('uc_total', 0))
        with col2:
            st.metric("Active Use Cases", stats.get('uc_active', 0))
        with col3:
            inactive = stats.get('uc_total', 0) - stats.get('uc_active', 0)
            st.metric("Inactive/Draft", inactive)
        with col4:
            threat_cats = stats.get('threat_categories', {})
            st.metric("Threat Categories", len(threat_cats))
        
        # Create tabs for different visualizations
        tab1, tab2, tab3 = st.tabs(["📊 Category Distribution", "📈 Trend Analysis", "🗂️ Detailed Table"])
        
        with tab1:
            # Threat category distribution
            if stats.get('threat_categories'):
                threat_df = pd.DataFrame.from_dict(
                    stats['threat_categories'], 
                    orient='index', 
                    columns=['Count']
                ).reset_index()
                threat_df.columns = ['Threat Category', 'Count']
                
                # Save to database cache for export
                if db_instance:
                    db_instance.cache_metrics(
                        f"category_dist_{datetime.now().strftime('%Y%m%d')}",
                        threat_df.to_dict('records'),
                        ttl_minutes=60
                    )
                
                # Create subplots
                fig = make_subplots(
                    rows=1, cols=2,
                    specs=[[{'type': 'pie'}, {'type': 'bar'}]],
                    subplot_titles=('📊 Pie Chart', '📈 Bar Chart')
                )
                
                # Pie chart
                fig.add_trace(
                    go.Pie(
                        labels=threat_df['Threat Category'],
                        values=threat_df['Count'],
                        hole=0.3,
                        textinfo='label+percent',
                        marker=dict(colors=px.colors.qualitative.Set3)
                    ),
                    row=1, col=1
                )
                
                # Bar chart
                fig.add_trace(
                    go.Bar(
                        x=threat_df['Threat Category'],
                        y=threat_df['Count'],
                        marker_color=px.colors.qualitative.Set3,
                        text=threat_df['Count'],
                        textposition='auto'
                    ),
                    row=1, col=2
                )
                
                fig.update_layout(
                    height=500,
                    showlegend=True,
                    title_text=f"Use Case Distribution by Threat Category (Total: {stats.get('uc_active', 0)})"
                )
                
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No threat category data available yet.")
        
        with tab2:
            # Placeholder for trend analysis
            st.info("📈 **Trend Analysis**")
            st.markdown("""
            **Planned Features:**
            - Monthly growth of use cases
            - Category trends over time
            - Most active threat categories
            - Completion rate metrics
            """)
            
            # Simulated trend data
            months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun']
            categories = ['Insider Threat', 'External Attack', 'Malware']
            
            trend_data = []
            for month in months:
                for category in categories:
                    trend_data.append({
                        'Month': month,
                        'Category': category,
                        'Count': np.random.randint(5, 20)
                    })
            
            trend_df = pd.DataFrame(trend_data)
            
            fig = px.line(
                trend_df, 
                x='Month', 
                y='Count', 
                color='Category',
                markers=True,
                title="Simulated Use Case Growth Trend (Example)"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with tab3:
            # Detailed table view
            if stats.get('threat_categories'):
                threat_df = pd.DataFrame.from_dict(
                    stats['threat_categories'], 
                    orient='index', 
                    columns=['Count']
                ).reset_index()
                threat_df.columns = ['Threat Category', 'Count']
                
                st.dataframe(
                    threat_df.sort_values('Count', ascending=False),
                    use_container_width=True,
                    column_config={
                        "Threat Category": st.column_config.TextColumn(
                            "Threat Category",
                            width="medium"
                        ),
                        "Count": st.column_config.NumberColumn(
                            "Count",
                            help="Number of use cases",
                            format="%d"
                        )
                    }
                )
            else:
                st.info("No detailed data available.")
        
        # Export options
        st.subheader("📥 Export Data")
        col1, col2 = st.columns(2)
        
        with col1:
            if stats.get('threat_categories'):
                threat_df = pd.DataFrame.from_dict(
                    stats['threat_categories'], 
                    orient='index', 
                    columns=['Count']
                ).reset_index()
                threat_df.columns = ['Threat Category', 'Count']
                
                csv = threat_df.to_csv(index=False)
                st.download_button(
                    label="📋 Download as CSV",
                    data=csv,
                    file_name=f"use_case_metrics_{datetime.now().strftime('%Y%m%d')}.csv",
                    mime="text/csv",
                    use_container_width=True
                )
        
        with col2:
            json_data = json.dumps(stats, indent=2)
            st.download_button(
                label="📄 Download as JSON",
                data=json_data,
                file_name=f"use_case_metrics_{datetime.now().strftime('%Y%m%d')}.json",
                mime="application/json",
                use_container_width=True
            )
    else:
        st.warning("Could not fetch Confluence data. Please check your connection settings.")

# ====================
# PAGE 3: DETECTION RULE QUERIES
# ====================

elif page == "🔍 Detection Rule Queries":
    st.title("🔍 Detection Rule Query Analyzer")
    
    # Query language selection
    query_language = st.selectbox(
        "Select Query Language",
        ["SPL (Splunk)", "KQL (Kusto/KQL)", "Lucene (Elasticsearch)", "SQLite", "Sigma"],
        index=0
    )
    
    # Create tabs for different sections
    tab1, tab2, tab3, tab4 = st.tabs(["📝 Write Query", "📊 Analyze Logs", "💾 Save/Load", "🎯 Templates"])
    
    with tab1:
        # Query editor
        col1, col2 = st.columns([3, 2])
        
        with col1:
            st.subheader("Query Editor")
            
            # Check if a query was loaded
            default_query = ""
            if st.session_state.selected_query:
                default_query = st.session_state.selected_query.get('query_text', '')
                st.session_state.selected_query = None  # Clear after use
            elif db_instance:
                # Get templates for selected language
                templates = db_instance.get_rule_templates(language=query_language.split()[0])
                default_query = templates[0]['template'] if templates else ""
            
            query = st.text_area(
                f"Write your {query_language.split()[0]} query:",
                value=default_query,
                height=200,
                key="query_editor",
                help=f"Enter your {query_language} query here"
            )
        
        with col2:
            st.subheader("Quick Reference")
            
            if db_instance:
                # Show available templates
                templates = db_instance.get_rule_templates(language=query_language.split()[0])
                if templates:
                    st.markdown("**Available Templates:**")
                    for template in templates[:5]:  # Show first 5
                        if st.button(f"📋 {template['name']}", key=f"template_{template['id']}"):
                            st.session_state.selected_query = template
                            st.rerun()
    
    with tab3:  # Save/Load tab
        st.subheader("💾 Save & Load Queries")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Save Current Query**")
            query_name = st.text_input("Query Name", value=f"{query_language}_query_{datetime.now().strftime('%H%M')}")
            query_description = st.text_area("Description", placeholder="Describe what this query detects")
            query_tags = st.text_input("Tags (comma separated)", placeholder="brute_force, authentication, windows")
            
            if st.button("💾 Save Query", use_container_width=True, key="save_query"):
                if query and query_name:
                    try:
                        if db_instance:
                            tags = [tag.strip() for tag in query_tags.split(',')] if query_tags else []
                            query_id = db_instance.save_query(
                                name=query_name,
                                description=query_description,
                                language=query_language,
                                query_text=query,
                                tags=tags
                            )
                            st.success(f"✅ Query saved with ID: {query_id}")
                            st.balloons()
                        else:
                            st.error("Database not available")
                    except Exception as e:
                        st.error(f"Failed to save query: {e}")
                else:
                    st.warning("Please provide both a query name and the query.")
        
        with col2:
            st.markdown("**Load Saved Query**")
            
            if db_instance:
                # Load saved queries from database
                saved_queries = db_instance.get_all_queries()
                
                if saved_queries:
                    # Filter by language
                    language_queries = [q for q in saved_queries 
                                      if q['query_language'] == query_language]
                    
                    if language_queries:
                        # Create a selection list with names
                        query_options = {f"{q['name']} (ID: {q['id']})": q for q in language_queries}
                        selected = st.selectbox(
                            "Select query",
                            options=list(query_options.keys())
                        )
                        
                        if selected:
                            selected_query = query_options[selected]
                            
                            # Display query info
                            with st.expander("Query Details", expanded=True):
                                st.write(f"**Description:** {selected_query['description']}")
                                st.write(f"**Created:** {selected_query['created_at']}")
                                if selected_query['tags']:
                                    tags = json.loads(selected_query['tags'])
                                    st.write(f"**Tags:** {', '.join(tags)}")
                            
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                if st.button("📂 Load Query", use_container_width=True):
                                    st.session_state.selected_query = selected_query
                                    st.rerun()
                            with col2:
                                if st.button("📊 View Stats", use_container_width=True):
                                    # Show execution stats
                                    st.info(f"Query ID: {selected_query['id']}")
                            with col3:
                                if st.button("🗑️ Delete", use_container_width=True):
                                    if db_instance.delete_query(selected_query['id']):
                                        st.success("Query deleted")
                                        st.rerun()
                    else:
                        st.info(f"No saved queries for {query_language}")
                else:
                    st.info("No saved queries found.")
            else:
                st.info("Database not available")
    
    with tab4:  # Templates tab
        st.subheader("🎯 Detection Rule Templates")
        
        if db_instance:
            # Filter templates
            col1, col2 = st.columns(2)
            with col1:
                template_language = st.selectbox(
                    "Language",
                    ["All", "SPL", "KQL", "Lucene", "SQLite", "Sigma"],
                    key="template_lang"
                )
            with col2:
                template_category = st.selectbox(
                    "Category",
                    ["All", "Authentication", "Malware", "Data Exfiltration", "Insider Threat", "Network"],
                    key="template_cat"
                )
            
            # Get filtered templates
            templates = db_instance.get_rule_templates(
                language=None if template_language == "All" else template_language,
                category=None if template_category == "All" else template_category
            )
            
            if templates:
                for template in templates:
                    with st.expander(f"📋 {template['name']} ({template['language']})", expanded=False):
                        col1, col2 = st.columns([3, 1])
                        with col1:
                            st.markdown(f"**Description:** {template['description']}")
                            st.markdown(f"**Category:** {template['category']}")
                            st.markdown(f"**Severity:** {template['severity']}")
                        with col2:
                            if st.button("Use Template", key=f"use_{template['id']}"):
                                st.session_state.selected_query = template
                                st.rerun()
                        
                        st.code(template['template'], language='text')
            else:
                st.info("No templates found for the selected filters.")
            
            # Add new template
            with st.expander("➕ Add New Template", expanded=False):
                with st.form("new_template_form"):
                    new_name = st.text_input("Template Name")
                    new_desc = st.text_area("Description")
                    new_lang = st.selectbox("Language", ["SPL", "KQL", "Lucene", "SQLite", "Sigma"])
                    new_category = st.selectbox("Category", ["Authentication", "Malware", "Data Exfiltration", "Insider Threat", "Network"])
                    new_severity = st.selectbox("Severity", ["High", "Medium", "Low", "Info"])
                    new_template = st.text_area("Template Code", height=150)
                    new_tags = st.text_input("Tags (comma separated)")
                    
                    if st.form_submit_button("Save Template"):
                        if new_name and new_template:
                            tags = [tag.strip() for tag in new_tags.split(',')] if new_tags else []
                            db_instance.add_rule_template(
                                name=new_name,
                                description=new_desc,
                                language=new_lang,
                                template=new_template,
                                category=new_category,
                                severity=new_severity,
                                tags=tags
                            )
                            st.success("Template saved!")
                            st.rerun()
        else:
            st.info("Database not available")

# ====================
# PAGE 4: INCIDENT RESPONSE BOT
# ====================

elif page == "🤖 Incident Response Bot":
    st.title("🤖 SOC Incident Response Assistant")
    
    # Chat container
    chat_container = st.container()
    
    with chat_container:
        # Display chat history
        for message in st.session_state.chat_history:
            with st.chat_message(message.get("role", "user")):
                st.markdown(message.get("content", ""))
    
    # Chat input
    if prompt := st.chat_input("Ask about incident response, investigation steps, or threat analysis..."):
        # Save user message to database
        if db_instance:
            try:
                db_instance.save_chat_message(
                    session_id=st.session_state.session_id,
                    role="user",
                    content=prompt,
                    metadata=json.dumps({"timestamp": datetime.now().isoformat()})
                )
            except Exception as e:
                logger.warning(f"Could not save chat message: {e}")
        
        # Add to session state
        st.session_state.chat_history.append({
            "role": "user",
            "content": prompt
        })
        
        # Display user message
        with chat_container:
            with st.chat_message("user"):
                st.markdown(prompt)
        
        # Generate assistant response
        with st.chat_message("assistant"):
            message_placeholder = st.empty()
            
            # Define common incident response scenarios
            response_templates = {
                "phishing": """
                **🎯 Phishing Incident Response:**
                
                **1. Initial Triage:**
                - Isolate affected systems
                - Preserve email headers and attachments
                - Check for credential compromise
                
                **2. Investigation:**
                - Analyze email headers (SPF, DKIM, DMARC)
                - Examine URLs and attachments in sandbox
                - Check email gateway logs
                
                **3. Containment:**
                - Quarantine malicious emails
                - Reset compromised credentials
                - Block malicious URLs/IPs
                
                **4. Remediation:**
                - Update email filtering rules
                - Conduct user awareness training
                - Review email security controls
                
                **📊 Relevant Metrics:**
                - Time to detection (TTD)
                - Number of affected users
                - Click-through rate
                """,
                
                "ransomware": """
                **🎯 Ransomware Incident Response:**
                
                **1. Immediate Actions:**
                - Isolate infected systems
                - Disconnect from network
                - Identify patient zero
                
                **2. Investigation:**
                - Analyze ransom note
                - Identify encryption method
                - Check for data exfiltration
                
                **3. Containment:**
                - Block C2 communications
                - Isolate backup systems
                - Preserve forensic evidence
                
                **4. Recovery:**
                - Restore from clean backups
                - Rebuild affected systems
                - Implement enhanced monitoring
                
                **🔗 Resources:**
                - No More Ransom Project
                - Local law enforcement contacts
                - Cyber insurance provider
                """,
                
                "insider": """
                **🎯 Insider Threat Response:**
                
                **1. Initial Assessment:**
                - Verify legitimate access vs. abuse
                - Review user role and permissions
                - Check for policy violations
                
                **2. Investigation:**
                - Audit user activity logs
                - Review data access patterns
                - Interview relevant parties
                
                **3. Containment:**
                - Temporarily suspend access
                - Preserve digital evidence
                - Secure sensitive data
                
                **4. Legal/HR Coordination:**
                - Follow disciplinary procedures
                - Coordinate with legal counsel
                - Update access controls
                
                **📋 Documentation:**
                - Chain of custody
                - Investigation report
                - Remediation actions
                """
            }
            
            # Check for keywords in prompt
            prompt_lower = prompt.lower()
            
            if "phishing" in prompt_lower:
                response = response_templates["phishing"]
            elif "ransomware" in prompt_lower:
                response = response_templates["ransomware"]
            elif "insider" in prompt_lower:
                response = response_templates["insider"]
            else:
                # Default response
                response = f"""
                **🤖 Incident Response Assistant**
                
                I can help you with:
                - **Phishing incidents**: Email analysis, URL investigation
                - **Ransomware**: Containment, recovery procedures
                - **Insider threats**: User activity monitoring, investigation
                - **Malware outbreaks**: IOC identification, eradication
                - **Data exfiltration**: Data loss prevention, investigation
                
                Try asking specific questions like:
                - "How do I investigate a phishing email?"
                - "What are the steps for ransomware containment?"
                - "How to handle an insider threat case?"
                """
            
            # Display the response
            message_placeholder.markdown(response)
            full_response = response
            
        # Save assistant response to database
        if db_instance:
            try:
                db_instance.save_chat_message(
                    session_id=st.session_state.session_id,
                    role="assistant",
                    content=full_response,
                    metadata=json.dumps({
                        "response_type": "incident_response",
                        "timestamp": datetime.now().isoformat()
                    })
                )
            except Exception as e:
                logger.warning(f"Could not save assistant response: {e}")
        
        # Add to session state
        st.session_state.chat_history.append({
            "role": "assistant",
            "content": full_response
        })
    
    # Quick action buttons
    st.subheader("🚀 Quick Actions")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("🔄 Clear Chat", use_container_width=True):
            st.session_state.chat_history = []
            if db_instance:
                try:
                    db_instance.clear_chat_history(st.session_state.session_id)
                except Exception as e:
                    logger.warning(f"Could not clear chat history: {e}")
            st.rerun()
    
    with col2:
        if st.button("📋 Generate IR Report", use_container_width=True):
            report_template = """
            **INCIDENT RESPONSE REPORT TEMPLATE**
            
            **1. Executive Summary**
            - Incident ID: [Auto-generate]
            - Severity: [Critical/High/Medium/Low]
            - Status: [Active/Contained/Resolved]
            
            **2. Timeline**
            - Detection Time: [Timestamp]
            - Response Time: [Timestamp]
            - Resolution Time: [Timestamp]
            
            **3. Impact Assessment**
            - Affected Systems: [List]
            - Data Compromised: [Yes/No]
            - Business Impact: [High/Medium/Low]
            
            **4. Actions Taken**
            - Immediate containment
            - Investigation steps
            - Remediation actions
            
            **5. Lessons Learned**
            - Detection gaps
            - Process improvements
            - Training needs
            """
            
            st.download_button(
                label="📄 Download Template",
                data=report_template,
                file_name="ir_report_template.md",
                mime="text/markdown",
                use_container_width=True
            )
    
    with col3:
        if st.button("🔗 Playbook Links", use_container_width=True):
            st.info("""
            **Useful Resources:**
            - [NIST Incident Response Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
            - [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)
            - [MITRE ATT&CK Framework](https://attack.mitre.org/)
            - [CIS Critical Security Controls](https://www.cisecurity.org/controls/)
            """)
    
    with col4:
        if st.button("📞 Escalation Contacts", use_container_width=True):
            st.info("""
            **Emergency Contacts:**
            - SOC Manager: [Contact]
            - Legal Counsel: [Contact]
            - PR/Communications: [Contact]
            - Law Enforcement: [Contact]
            - Cyber Insurance: [Contact]
            """)

# ====================
# PAGE 5: ANALYTICS DASHBOARD (FIXED VERSION)
# ====================

elif page == "📈 Analytics Dashboard":
    st.title("📈 SOC Analytics Dashboard")
    
    if not db_instance:
        st.warning("Database not available. Please initialize the database first.")
        st.stop()
    
    try:
        # Get analytics data with error handling
        analytics_data = db_instance.get_query_analytics(days=30)
        
        # Overall stats with safe defaults
        st.subheader("📊 Overall Statistics")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            try:
                total_queries = len(db_instance.get_all_queries())
                st.metric("Total Saved Queries", total_queries)
            except:
                st.metric("Total Saved Queries", 0)
        
        with col2:
            try:
                success_stats = analytics_data.get('success_stats', {})
                success_rate = success_stats.get('success_rate', 0)
                if success_rate is None:
                    success_rate = 0
                st.metric("Query Success Rate", f"{float(success_rate):.1f}%")
            except:
                st.metric("Query Success Rate", "0.0%")
        
        with col3:
            try:
                total_executions = analytics_data.get('success_stats', {}).get('total', 0)
                if total_executions is None:
                    total_executions = 0
                st.metric("Total Executions", int(total_executions))
            except:
                st.metric("Total Executions", 0)
        
        with col4:
            try:
                top_queries = analytics_data.get('top_queries', [])
                if top_queries:
                    avg_duration = sum(q.get('avg_duration', 0) for q in top_queries if q.get('avg_duration')) / max(len(top_queries), 1)
                    st.metric("Avg Duration", f"{float(avg_duration):.0f}ms")
                else:
                    st.metric("Avg Duration", "0ms")
            except:
                st.metric("Avg Duration", "0ms")
        
        # Top queries
        st.subheader("🏆 Top 10 Most Used Queries")
        top_queries = analytics_data.get('top_queries', [])
        
        if top_queries:
            try:
                # Clean the data before creating DataFrame
                cleaned_queries = []
                for query in top_queries:
                    if query:  # Skip None entries
                        cleaned_query = {
                            'name': str(query.get('name', 'Unknown')) if query.get('name') else 'Unknown',
                            'query_language': str(query.get('query_language', 'Unknown')) if query.get('query_language') else 'Unknown',
                            'execution_count': int(query.get('execution_count', 0)) if query.get('execution_count') else 0,
                            'avg_duration': float(query.get('avg_duration', 0)) if query.get('avg_duration') else 0,
                            'avg_results': float(query.get('avg_results', 0)) if query.get('avg_results') else 0
                        }
                        cleaned_queries.append(cleaned_query)
                
                if cleaned_queries:
                    top_df = pd.DataFrame(cleaned_queries)
                    st.dataframe(top_df, use_container_width=True)
                    
                    # Visualization
                    fig = px.bar(
                        top_df,
                        x='name',
                        y='execution_count',
                        color='query_language',
                        title="Query Execution Count by Language"
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No valid query execution data available.")
            except Exception as e:
                st.error(f"Error processing top queries: {e}")
                st.info("Could not display query data due to formatting issues.")
        else:
            st.info("No query execution data available yet.")
        
        # Language distribution
        st.subheader("🌐 Query Language Distribution")
        lang_dist = analytics_data.get('language_distribution', [])
        
        if lang_dist:
            try:
                # Clean language distribution data
                cleaned_lang_dist = []
                for lang in lang_dist:
                    if lang:  # Skip None entries
                        cleaned_lang = {
                            'query_language': str(lang.get('query_language', 'Unknown')) if lang.get('query_language') else 'Unknown',
                            'count': int(lang.get('count', 0)) if lang.get('count') else 0
                        }
                        cleaned_lang_dist.append(cleaned_lang)
                
                if cleaned_lang_dist:
                    lang_df = pd.DataFrame(cleaned_lang_dist)
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        fig = px.pie(
                            lang_df,
                            values='count',
                            names='query_language',
                            title="Query Language Distribution"
                        )
                        st.plotly_chart(fig, use_container_width=True)
                    
                    with col2:
                        fig = px.bar(
                            lang_df,
                            x='query_language',
                            y='count',
                            color='query_language',
                            title="Query Count by Language"
                        )
                        st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No valid language distribution data.")
            except Exception as e:
                st.error(f"Error processing language distribution: {e}")
        else:
            st.info("No language distribution data available.")
        
        # Recent activity
        st.subheader("📅 Recent Activity")
        
        # Show database info
        if db_instance:
            try:
                # Get some basic stats
                saved_queries = db_instance.get_all_queries()
                chat_history = db_instance.get_chat_history(st.session_state.session_id, limit=100)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Queries in DB", len(saved_queries))
                with col2:
                    st.metric("Chat Messages", len(chat_history))
                with col3:
                    # Count active sessions (simplified)
                    st.metric("Active Session", 1)
            except:
                pass
        
        # Database maintenance button
        if st.button("🧹 Run Database Maintenance", use_container_width=True):
            try:
                db_instance.clear_expired_metrics()
                st.success("Database maintenance completed!")
                st.rerun()
            except Exception as e:
                st.error(f"Maintenance failed: {e}")
            
    except Exception as e:
        st.error(f"Could not load analytics data: {e}")
        st.info("Please make sure the database is properly initialized.")
        
        # Debug information
        with st.expander("Debug Information", expanded=False):
            try:
                st.write("Database instance type:", type(db_instance))
                if db_instance:
                    # Try a simple query to test
                    test_queries = db_instance.get_all_queries()
                    st.write("Number of saved queries:", len(test_queries))
                    
                    # Test the analytics function directly
                    try:
                        test_analytics = db_instance.get_query_analytics(days=7)
                        st.write("Analytics data structure:", test_analytics)
                    except Exception as analytics_error:
                        st.write("Analytics function error:", analytics_error)
                else:
                    st.write("Database instance is None")
            except Exception as debug_error:
                st.write("Debug error:", debug_error)

# ====================
# MAIN EXECUTION
# ====================

if __name__ == "__main__":
    # Initialize database maintenance
    if db_instance:
        try:
            db_instance.clear_expired_metrics()
        except Exception as e:
            logger.warning(f"Database maintenance error: {e}")
