import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import sqlite3
import json
import tempfile
import os
import re
from typing import Optional
import requests

# Set page config
st.set_page_config(
    page_title="SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E3A8A;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #F3F4F6;
        padding: 1.5rem;
        border-radius: 10px;
        border-left: 5px solid #3B82F6;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 2rem;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: #F3F4F6;
        border-radius: 5px 5px 0px 0px;
        gap: 1px;
        padding-top: 10px;
        padding-bottom: 10px;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'use_cases' not in st.session_state:
    st.session_state.use_cases = []
if 'detection_rules' not in st.session_state:
    st.session_state.detection_rules = []
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []
if 'uploaded_file' not in st.session_state:
    st.session_state.uploaded_file = None

# Sample data for demonstration
def load_sample_data():
    """Load sample data for demonstration"""
    # Sample use cases data
    threat_categories = ['Malware', 'Phishing', 'Insider Threat', 'DDoS', 
                        'Data Exfiltration', 'Credential Theft', 'Lateral Movement']
    
    sample_use_cases = []
    for i in range(100):
        category = threat_categories[i % len(threat_categories)]
        sample_use_cases.append({
            'id': f'UC-{i+1:03d}',
            'title': f'{category} Detection Rule #{i+1}',
            'category': category,
            'severity': ['High', 'Medium', 'Low'][i % 3],
            'created_date': (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d'),
            'status': 'Active' if i % 5 != 0 else 'Inactive',
            'coverage': ['Endpoint', 'Network', 'Cloud', 'Email'][i % 4]
        })
    
    st.session_state.use_cases = sample_use_cases
    
    # Sample detection rules
    sample_rules = [
        {
            'id': 'SPL-001',
            'name': 'Suspicious PowerShell Execution',
            'query': 'index=windows EventCode=4104 | stats count by host',
            'language': 'SPL',
            'description': 'Detects suspicious PowerShell execution patterns',
            'category': 'Endpoint Security'
        },
        {
            'id': 'KQL-001',
            'name': 'Failed Login Attempts',
            'query': 'SigninLogs | where ResultType == "50057" | summarize count() by UserPrincipalName, IPAddress',
            'language': 'KQL',
            'description': 'Detects multiple failed login attempts',
            'category': 'Identity'
        },
        {
            'id': 'LUCENE-001',
            'name': 'Brute Force Attacks',
            'query': 'event.action:"authentication_failure" AND destination.ip:*',
            'language': 'Lucene',
            'description': 'Detects brute force authentication attempts',
            'category': 'Network Security'
        }
    ]
    st.session_state.detection_rules = sample_rules

# Load sample data if empty
if not st.session_state.use_cases:
    load_sample_data()

# Sidebar navigation
st.sidebar.image("https://img.icons8.com/color/96/000000/shield.png", width=100)
st.sidebar.title("SOC Dashboard")
menu = st.sidebar.radio(
    "Navigation",
    ["🏠 Home Dashboard", "📊 Use Case Metrics", "🔍 Detection Rule Queries", "🤖 IR Assistant", "📈 Reports"]
)

# Home Dashboard
if menu == "🏠 Home Dashboard":
    st.markdown('<h1 class="main-header">🛡️ SOC Security Operations Center Dashboard</h1>', unsafe_allow_html=True)
    
    # Top Metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Total Use Cases", len(st.session_state.use_cases), "+12")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        active_cases = len([uc for uc in st.session_state.use_cases if uc['status'] == 'Active'])
        st.metric("Active Use Cases", active_cases, "+3")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        high_sev = len([uc for uc in st.session_state.use_cases if uc['severity'] == 'High'])
        st.metric("High Severity", high_sev, "-2")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col4:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Detection Rules", len(st.session_state.detection_rules), "+5")
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Charts for Home Dashboard
    col1, col2 = st.columns(2)
    
    with col1:
        # Severity distribution
        severity_counts = pd.DataFrame(st.session_state.use_cases)['severity'].value_counts().reset_index()
        severity_counts.columns = ['Severity', 'Count']
        
        fig1 = px.pie(severity_counts, values='Count', names='Severity', 
                     title='Use Cases by Severity Level',
                     color='Severity',
                     color_discrete_map={'High': '#EF4444', 'Medium': '#F59E0B', 'Low': '#10B981'})
        st.plotly_chart(fig1, use_container_width=True)
    
    with col2:
        # Recent use cases table
        st.subheader("Recent Use Cases")
        recent_cases = pd.DataFrame(st.session_state.use_cases[-10:])
        st.dataframe(recent_cases[['id', 'title', 'category', 'severity', 'status']], 
                    use_container_width=True)

# Use Case Metrics Dashboard
elif menu == "📊 Use Case Metrics":
    st.title("📊 Use Case Metrics Dashboard")
    
    # Convert to DataFrame
    df_use_cases = pd.DataFrame(st.session_state.use_cases)
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        selected_category = st.multiselect(
            "Filter by Category",
            options=df_use_cases['category'].unique(),
            default=df_use_cases['category'].unique()
        )
    
    with col2:
        selected_severity = st.multiselect(
            "Filter by Severity",
            options=df_use_cases['severity'].unique(),
            default=df_use_cases['severity'].unique()
        )
    
    with col3:
        selected_status = st.multiselect(
            "Filter by Status",
            options=df_use_cases['status'].unique(),
            default=['Active']
        )
    
    # Apply filters
    filtered_df = df_use_cases[
        (df_use_cases['category'].isin(selected_category)) &
        (df_use_cases['severity'].isin(selected_severity)) &
        (df_use_cases['status'].isin(selected_status))
    ]
    
    # Metrics row
    st.subheader("Summary Metrics")
    metrics_col1, metrics_col2, metrics_col3, metrics_col4 = st.columns(4)
    
    with metrics_col1:
        st.metric("Total Filtered", len(filtered_df))
    
    with metrics_col2:
        categories_count = filtered_df['category'].nunique()
        st.metric("Categories", categories_count)
    
    with metrics_col3:
        high_sev_filtered = len(filtered_df[filtered_df['severity'] == 'High'])
        st.metric("High Severity", high_sev_filtered)
    
    with metrics_col4:
        active_filtered = len(filtered_df[filtered_df['status'] == 'Active'])
        st.metric("Active", active_filtered)
    
    # Tabs for different visualizations
    tab1, tab2, tab3 = st.tabs(["📈 Charts", "📋 Data Table", "📅 Timeline"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            # Category distribution bar chart
            category_counts = filtered_df['category'].value_counts().reset_index()
            category_counts.columns = ['Category', 'Count']
            
            fig_cat = px.bar(category_counts, x='Category', y='Count',
                           title='Use Cases by Threat Category',
                           color='Count',
                           color_continuous_scale='Blues')
            fig_cat.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig_cat, use_container_width=True)
        
        with col2:
            # Coverage distribution
            coverage_counts = filtered_df['coverage'].value_counts().reset_index()
            coverage_counts.columns = ['Coverage', 'Count']
            
            fig_cov = px.pie(coverage_counts, values='Count', names='Coverage',
                           title='Use Cases by Coverage Area',
                           hole=0.4)
            st.plotly_chart(fig_cov, use_container_width=True)
    
    with tab2:
        # Detailed data table
        st.subheader("Detailed Use Case Information")
        st.dataframe(filtered_df, use_container_width=True)
        
        # Export options
        col1, col2 = st.columns(2)
        with col1:
            if st.button("📥 Export as CSV"):
                csv = filtered_df.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=f"use_cases_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
        with col2:
            if st.button("📊 Export as JSON"):
                json_data = filtered_df.to_json(orient='records', indent=2)
                st.download_button(
                    label="Download JSON",
                    data=json_data,
                    file_name=f"use_cases_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
    
    with tab3:
        # Timeline view
        st.subheader("Use Case Creation Timeline")
        
        # Aggregate by date
        timeline_data = filtered_df.copy()
        timeline_data['created_date'] = pd.to_datetime(timeline_data['created_date'])
        timeline_counts = timeline_data.groupby('created_date').size().reset_index()
        timeline_counts.columns = ['Date', 'Count']
        timeline_counts = timeline_counts.sort_values('Date')
        
        fig_timeline = px.line(timeline_counts, x='Date', y='Count',
                              title='Use Case Creation Timeline',
                              markers=True)
        st.plotly_chart(fig_timeline, use_container_width=True)

# Detection Rule Queries
elif menu == "🔍 Detection Rule Queries":
    st.title("🔍 Detection Rule Query Playground")
    
    tab1, tab2, tab3, tab4 = st.tabs(["📝 Query Editor", "📁 Log Analyzer", "📚 Rule Library", "⚡ Quick Tests"])
    
    with tab1:
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.subheader("Query Editor")
            
            # Query language selection
            query_language = st.selectbox(
                "Query Language",
                ["SPL (Splunk)", "KQL (Kusto)", "Lucene", "SQL", "YARA", "Sigma"]
            )
            
            # Query input
            query = st.text_area(
                "Write your query here:",
                height=200,
                placeholder="Enter your detection rule query..."
            )
            
            # Query parameters
            with st.expander("Query Parameters"):
                param_col1, param_col2 = st.columns(2)
                with param_col1:
                    time_range = st.selectbox("Time Range", ["Last 24 hours", "Last 7 days", "Last 30 days", "Custom"])
                    if time_range == "Custom":
                        start_date = st.date_input("Start Date")
                        end_date = st.date_input("End Date")
                
                with param_col2:
                    result_limit = st.number_input("Result Limit", min_value=10, max_value=10000, value=1000)
            
            # Action buttons
            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button("▶️ Run Query", type="primary", use_container_width=True):
                    if query:
                        st.success(f"Running {query_language} query...")
                        # Here you would add actual query execution logic
                        # For demo, show sample results
                        sample_results = pd.DataFrame({
                            'timestamp': pd.date_range(end=pd.Timestamp.now(), periods=20, freq='h'),
                            'event_type': ['login', 'process', 'network', 'file_access'] * 5,
                            'source_ip': ['192.168.1.' + str(i) for i in range(1, 21)],
                            'destination_ip': ['10.0.0.' + str(i) for i in range(1, 21)],
                            'user': ['user' + str(i) for i in range(1, 21)],
                            'action': ['success', 'failure', 'success', 'failure'] * 5
                        })
                        st.dataframe(sample_results, use_container_width=True)
                    else:
                        st.warning("Please enter a query first")
            
            with col2:
                if st.button("💾 Save Rule", use_container_width=True):
                    if query:
                        rule_name = st.text_input("Rule Name", key="rule_name")
                        rule_description = st.text_area("Description", key="rule_desc")
                        if st.button("Confirm Save"):
                            new_rule = {
                                'id': f'RULE-{len(st.session_state.detection_rules) + 1:03d}',
                                'name': rule_name,
                                'query': query,
                                'language': query_language,
                                'description': rule_description,
                                'created_date': datetime.now().strftime('%Y-%m-%d')
                            }
                            st.session_state.detection_rules.append(new_rule)
                            st.success("Rule saved successfully!")
            
            with col3:
                if st.button("🔄 Validate Syntax", use_container_width=True):
                    if query:
                        # Basic syntax validation
                        if query.strip():
                            st.success("Syntax appears valid")
                        else:
                            st.error("Query is empty")
        
        with col2:
            st.subheader("Query Help")
            
            # Language-specific help
            if query_language == "SPL (Splunk)":
                st.markdown("""
                **SPL Examples:**
                ```
                index=security sourcetype=win*
                | stats count by host
                | where count > 100
                
                index=firewall action=block
                | timechart count by src_ip
                ```
                """)
            
            elif query_language == "KQL (Kusto)":
                st.markdown("""
                **KQL Examples:**
                ```
                SecurityEvent
                | where EventID == 4625
                | summarize FailedLogins=count() by Account
                | where FailedLogins > 5
                
                SigninLogs
                | where ResultType == "50057"
                | project TimeGenerated, UserPrincipalName, IPAddress
                ```
                """)
            
            elif query_language == "Lucene":
                st.markdown("""
                **Lucene Examples:**
                ```
                event.action:"authentication_failure" 
                AND source.ip:192.168.*
                
                (event.type:"process" AND process.name:"powershell.exe") 
                OR process.name:"cmd.exe"
                ```
                """)
    
    with tab2:
        st.subheader("Log File Analyzer")
        
        uploaded_file = st.file_uploader(
            "Upload log file for analysis",
            type=['txt', 'csv', 'json', 'log', 'xml'],
            help="Upload logs in CSV, JSON, or plain text format"
        )
        
        if uploaded_file is not None:
            # Save uploaded file temporarily
            with tempfile.NamedTemporaryFile(delete=False, suffix='.log') as tmp_file:
                tmp_file.write(uploaded_file.getvalue())
                tmp_path = tmp_file.name
            
            st.success(f"File uploaded successfully: {uploaded_file.name}")
            
            # Try to parse the file
            try:
                if uploaded_file.name.endswith('.csv'):
                    df_logs = pd.read_csv(uploaded_file)
                elif uploaded_file.name.endswith('.json'):
                    df_logs = pd.read_json(uploaded_file)
                else:
                    # Try to parse as plain text
                    content = uploaded_file.getvalue().decode('utf-8')
                    lines = content.split('\n')
                    df_logs = pd.DataFrame({'log_entry': lines})
                
                st.subheader("Log Preview")
                st.dataframe(df_logs.head(20), use_container_width=True)
                
                # Basic log analysis
                st.subheader("Quick Analysis")
                
                if 'timestamp' in df_logs.columns:
                    try:
                        df_logs['timestamp'] = pd.to_datetime(df_logs['timestamp'])
                        time_dist = df_logs['timestamp'].dt.hour.value_counts().sort_index()
                        fig_time = px.bar(x=time_dist.index, y=time_dist.values,
                                        title='Log Distribution by Hour')
                        st.plotly_chart(fig_time, use_container_width=True)
                    except:
                        pass
                
                # Text analysis
                if 'message' in df_logs.columns or 'log_entry' in df_logs.columns:
                    col_name = 'message' if 'message' in df_logs.columns else 'log_entry'
                    common_terms = df_logs[col_name].str.lower().str.extractall(r'(\b\w{5,}\b)')[0].value_counts().head(10)
                    fig_terms = px.bar(x=common_terms.index, y=common_terms.values,
                                      title='Most Common Terms')
                    st.plotly_chart(fig_terms, use_container_width=True)
                
                # Clean up
                os.unlink(tmp_path)
                
            except Exception as e:
                st.error(f"Error parsing file: {str(e)}")
    
    with tab3:
        st.subheader("Saved Detection Rules")
        
        if st.session_state.detection_rules:
            for rule in st.session_state.detection_rules:
                with st.expander(f"{rule['id']} - {rule['name']} ({rule['language']})"):
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.markdown(f"**Description:** {rule['description']}")
                        st.code(rule['query'], language='text')
                    with col2:
                        if st.button("📋 Copy", key=f"copy_{rule['id']}"):
                            st.success("Query copied to clipboard!")
                        if st.button("▶️ Run", key=f"run_{rule['id']}"):
                            st.info(f"Running rule: {rule['name']}")
        else:
            st.info("No saved rules yet. Create one in the Query Editor tab.")

# Incident Response Assistant
elif menu == "🤖 IR Assistant":
    st.title("🤖 Incident Response Assistant")
    
    # Initialize Ollama/Local LLM connection
    @st.cache_resource
    def init_llm():
        try:
            # Try to connect to Ollama
            response = requests.get("http://localhost:11434/api/tags")
            if response.status_code == 200:
                return "ollama"
        except:
            pass
        
        # Fallback to local model or API
        return "local"
    
    llm_type = init_llm()
    
    # Incident types
    incident_types = [
        "Malware Infection",
        "Phishing Attack",
        "Data Breach",
        "DDoS Attack",
        "Insider Threat",
        "Ransomware",
        "Account Compromise",
        "Network Intrusion",
        "Web Application Attack",
        "IoT Compromise"
    ]
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Chat interface
        st.subheader("Incident Response Guidance")
        
        # Initialize chat history
        if 'ir_chat_history' not in st.session_state:
            st.session_state.ir_chat_history = []
        
        # Display chat history
        for message in st.session_state.ir_chat_history:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])
        
        # Chat input
        if prompt := st.chat_input("Describe the incident or ask for guidance..."):
            # Add user message to chat history
            st.session_state.ir_chat_history.append({"role": "user", "content": prompt})
            
            # Display user message
            with st.chat_message("user"):
                st.markdown(prompt)
            
            # Generate response
            with st.chat_message("assistant"):
                with st.spinner("Analyzing incident..."):
                    # Sample IR responses (replace with actual LLM integration)
                    ir_responses = {
                        "malware": """
                        **Malware Infection Response Checklist:**
                        
                        1. **Isolation**: Immediately isolate affected systems from network
                        2. **Containment**: Block malicious IPs/domains at firewall
                        3. **Identification**: Collect malware samples for analysis
                        4. **Eradication**: Remove malware using AV tools or manual cleanup
                        5. **Recovery**: Restore systems from clean backups
                        6. **Lessons Learned**: Document incident and update policies
                        
                        **Immediate Actions:**
                        - Run memory and disk forensics
                        - Check for lateral movement
                        - Review AV/EDR logs for detection
                        """,
                        "phishing": """
                        **Phishing Incident Response:**
                        
                        1. **Email Analysis**: Check headers, attachments, links
                        2. **User Awareness**: Notify users not to click
                        3. **Block Indicators**: Block sender, URLs, attachments
                        4. **Credential Reset**: Reset potentially compromised credentials
                        5. **Log Review**: Check for suspicious logins
                        6. **Reporting**: Report to abuse@ domains and authorities if needed
                        """,
                        "ransomware": """
                        **Ransomware Response Protocol:**
                        
                        🚨 **CRITICAL ACTIONS:**
                        1. **DISCONNECT** affected systems immediately
                        2. **IDENTIFY** patient zero and propagation method
                        3. **PRESERVE** evidence - don't power off encrypted systems
                        4. **DO NOT PAY** ransom - consult legal/federal guidance
                        5. **ACTIVATE** incident response team and management
                        
                        **Forensic Collection:**
                        - Memory dumps before shutdown
                        - Network traffic captures
                        - Ransomware note and sample
                        """
                    }
                    
                    # Simple keyword matching for demo
                    response_text = "**Incident Response Guidance:**\n\n"
                    
                    if any(word in prompt.lower() for word in ['malware', 'virus', 'trojan']):
                        response_text += ir_responses['malware']
                    elif any(word in prompt.lower() for word in ['phish', 'email', 'spoof']):
                        response_text += ir_responses['phishing']
                    elif any(word in prompt.lower() for word in ['ransom', 'encrypt', 'bitcoin']):
                        response_text += ir_responses['ransomware']
                    else:
                        response_text += """
                        **General Incident Response Framework:**
                        
                        1. **Preparation**: Ensure IR plan and tools are ready
                        2. **Identification**: Detect and confirm the incident
                        3. **Containment**: Limit the scope and damage
                        4. **Eradication**: Remove the threat
                        5. **Recovery**: Restore normal operations
                        6. **Lessons Learned**: Improve based on findings
                        
                        **Please provide more details about:**
                        - Type of attack
                        - Affected systems
                        - Timeline of events
                        - Current impact
                        """
                    
                    st.markdown(response_text)
            
            # Add assistant response to chat history
            st.session_state.ir_chat_history.append({"role": "assistant", "content": response_text})
    
    with col2:
        st.subheader("Quick Actions")
        
        # Incident type selection
        selected_incident = st.selectbox("Select Incident Type", incident_types)
        
        # Quick response templates
        if st.button("🚨 Generate Response Plan"):
            st.info(f"Generating response plan for {selected_incident}...")
            # This would trigger LLM to generate specific response plan
        
        if st.button("📋 Get Checklist"):
            st.info(f"Getting checklist for {selected_incident}...")
        
        if st.button("📞 Escalate to Team"):
            st.success("Incident escalated to SOC team!")
        
        st.divider()
        
        # Enrichment tools
        st.subheader("Enrichment Tools")
        
        ioc_input = st.text_input("Enter IOC (IP, Domain, Hash):")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🔍 Lookup"):
                if ioc_input:
                    st.info(f"Looking up: {ioc_input}")
                    # Add actual enrichment API calls here
        
        with col2:
            if st.button("📊 Analyze"):
                if ioc_input:
                    st.info(f"Analyzing: {ioc_input}")
        
        st.divider()
        
        # LLM Status
        st.subheader("AI Assistant Status")
        if llm_type == "ollama":
            st.success("✅ Connected to Ollama")
            model_name = st.selectbox("Select Model", ["llama2", "mistral", "codellama"])
        else:
            st.warning("⚠️ Using local knowledge base")
            st.info("For better responses, install Ollama and run:\n```bash\nollama run llama2\n```")

# Reports
elif menu == "📈 Reports":
    st.title("📈 SOC Reports")
    
    tab1, tab2, tab3 = st.tabs(["📅 Daily Report", "📊 Weekly Summary", "📋 Custom Report"])
    
    with tab1:
        st.subheader("Daily SOC Report")
        report_date = st.date_input("Select Date", datetime.now())
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Alerts Generated", 245)
            st.metric("False Positives", 18)
            st.metric("Incidents Created", 7)
        
        with col2:
            st.metric("MTTD (min)", 8.5, -1.2)
            st.metric("MTTR (hours)", 2.3, -0.5)
            st.metric("SLA Compliance", "98.2%", 0.3)
        
        if st.button("📥 Generate Daily Report"):
            st.success("Daily report generated successfully!")
    
    with tab2:
        st.subheader("Weekly Summary")
        # Add weekly summary charts and metrics
    
    with tab3:
        st.subheader("Custom Report Generator")
        # Add custom report generation options

# Footer
st.sidebar.divider()
st.sidebar.info(
    """
    **SOC Dashboard v2.0**
    - Use Case Metrics
    - Detection Rule Playground
    - IR Assistant
    - Reporting
    """
)

# Add auto-refresh option
if st.sidebar.checkbox("🔄 Auto-refresh (30s)"):
    st.rerun()
