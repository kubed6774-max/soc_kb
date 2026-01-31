"""
Database module for SOC Dashboard using SQLite.
Handles persistent storage for queries, chat history, and analytics.
"""

import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from contextlib import contextmanager
import logging

logger = logging.getLogger(__name__)

class SOCDatabase:
    def __init__(self, db_path: str = "soc_dashboard.db"):
        self.db_path = db_path
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Return rows as dictionaries
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()
    
    def init_database(self):
        """Initialize database tables."""
        with self.get_connection() as conn:
            # Saved queries table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS saved_queries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    query_language TEXT NOT NULL,
                    query_text TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    tags TEXT,  -- JSON array of tags
                    is_favorite BOOLEAN DEFAULT 0,
                    user_id TEXT DEFAULT 'default'
                )
            ''')
            
            # Query executions log
            conn.execute('''
                CREATE TABLE IF NOT EXISTS query_executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query_id INTEGER,
                    execution_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    duration_ms INTEGER,
                    result_count INTEGER,
                    success BOOLEAN,
                    error_message TEXT,
                    FOREIGN KEY (query_id) REFERENCES saved_queries(id)
                )
            ''')
            
            # Chat history
            conn.execute('''
                CREATE TABLE IF NOT EXISTS chat_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,  -- 'user' or 'assistant'
                    content TEXT NOT NULL,
                    message_type TEXT DEFAULT 'text',  -- text, query, command
                    metadata TEXT,  -- JSON metadata
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_id TEXT DEFAULT 'default'
                )
            ''')
            
            # Use case metrics cache
            conn.execute('''
                CREATE TABLE IF NOT EXISTS metrics_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_key TEXT UNIQUE NOT NULL,
                    metric_value TEXT NOT NULL,  -- JSON data
                    expires_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Uploaded log files metadata
            conn.execute('''
                CREATE TABLE IF NOT EXISTS log_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    file_size INTEGER,
                    row_count INTEGER,
                    columns TEXT,  -- JSON array
                    upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_id TEXT DEFAULT 'default'
                )
            ''')
            
            # Detection rule templates
            conn.execute('''
                CREATE TABLE IF NOT EXISTS rule_templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    language TEXT NOT NULL,
                    template TEXT NOT NULL,
                    category TEXT,
                    severity TEXT,
                    tags TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes
            conn.execute('CREATE INDEX IF NOT EXISTS idx_queries_user ON saved_queries(user_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_queries_language ON saved_queries(query_language)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_chat_session ON chat_history(session_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_metrics_key ON metrics_cache(metric_key)')
            
            # Insert default rule templates
            self._insert_default_templates(conn)
    
    def _insert_default_templates(self, conn):
        """Insert default detection rule templates."""
        templates = [
            {
                'name': 'Failed Login Brute Force',
                'description': 'Detect multiple failed login attempts',
                'language': 'SPL',
                'category': 'Authentication',
                'severity': 'High',
                'template': '''index=security sourcetype=windows_security EventCode=4625 
| stats count by user, src_ip 
| where count > 5 
| table user, src_ip, count''',
                'tags': '["authentication", "brute_force", "windows"]'
            },
            {
                'name': 'Suspicious Process Execution',
                'description': 'Detect execution of suspicious processes',
                'language': 'KQL',
                'category': 'Malware',
                'severity': 'Medium',
                'template': '''SecurityEvent 
| where EventID == 4688 
| where NewProcessName contains "powershell" or NewProcessName contains "cmd" 
| where ParentProcessName != "explorer.exe"''',
                'tags': '["process", "execution", "malware"]'
            }
        ]
        
        for template in templates:
            conn.execute('''
                INSERT OR IGNORE INTO rule_templates 
                (name, description, language, template, category, severity, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                template['name'],
                template['description'],
                template['language'],
                template['template'],
                template['category'],
                template['severity'],
                template['tags']
            ))
    
    # ====================
    # SAVED QUERIES METHODS
    # ====================
    
    def save_query(self, name: str, description: str, language: str, 
                   query_text: str, tags: List[str] = None, 
                   user_id: str = 'default') -> int:
        """Save a new query."""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                INSERT INTO saved_queries 
                (name, description, query_language, query_text, tags, user_id)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                name, 
                description, 
                language, 
                query_text, 
                json.dumps(tags or []), 
                user_id
            ))
            return cursor.lastrowid
    
    def get_all_queries(self, user_id: str = 'default') -> List[Dict]:
        """Get all saved queries for a user."""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT * FROM saved_queries 
                WHERE user_id = ? 
                ORDER BY updated_at DESC
            ''', (user_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_query_by_id(self, query_id: int) -> Optional[Dict]:
        """Get a specific query by ID."""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT * FROM saved_queries WHERE id = ?
            ''', (query_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def update_query(self, query_id: int, **kwargs) -> bool:
        """Update a saved query."""
        if not kwargs:
            return False
        
        set_clause = ', '.join([f"{k} = ?" for k in kwargs.keys()])
        values = list(kwargs.values())
        values.append(query_id)
        
        with self.get_connection() as conn:
            cursor = conn.execute(f'''
                UPDATE saved_queries 
                SET {set_clause}, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', values)
            return cursor.rowcount > 0
    
    def delete_query(self, query_id: int) -> bool:
        """Delete a saved query."""
        with self.get_connection() as conn:
            cursor = conn.execute('DELETE FROM saved_queries WHERE id = ?', (query_id,))
            return cursor.rowcount > 0
    
    def log_query_execution(self, query_id: int, duration_ms: int, 
                           result_count: int, success: bool, 
                           error_message: str = None):
        """Log query execution for analytics."""
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO query_executions 
                (query_id, duration_ms, result_count, success, error_message)
                VALUES (?, ?, ?, ?, ?)
            ''', (query_id, duration_ms, result_count, success, error_message))
    
    # ====================
    # CHAT HISTORY METHODS
    # ====================
    
    def save_chat_message(self, session_id: str, role: str, content: str, 
                         message_type: str = 'text', metadata: Dict = None):
        """Save a chat message to history."""
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO chat_history 
                (session_id, role, content, message_type, metadata)
                VALUES (?, ?, ?, ?, ?)
            ''', (session_id, role, content, message_type, 
                  json.dumps(metadata or {})))
    
    def get_chat_history(self, session_id: str, limit: int = 50) -> List[Dict]:
        """Get chat history for a session."""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT * FROM chat_history 
                WHERE session_id = ? 
                ORDER BY created_at ASC
                LIMIT ?
            ''', (session_id, limit))
            return [dict(row) for row in cursor.fetchall()]
    
    def clear_chat_history(self, session_id: str):
        """Clear chat history for a session."""
        with self.get_connection() as conn:
            conn.execute('DELETE FROM chat_history WHERE session_id = ?', (session_id,))
    
    # ====================
    # METRICS CACHE METHODS
    # ====================
    
    def cache_metrics(self, key: str, value: Dict, ttl_minutes: int = 5):
        """Cache metrics data with TTL."""
        expires_at = datetime.now().timestamp() + (ttl_minutes * 60)
        
        with self.get_connection() as conn:
            conn.execute('''
                INSERT OR REPLACE INTO metrics_cache 
                (metric_key, metric_value, expires_at, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (key, json.dumps(value), expires_at))
    
    def get_cached_metrics(self, key: str) -> Optional[Dict]:
        """Get cached metrics if not expired."""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT metric_value, expires_at FROM metrics_cache 
                WHERE metric_key = ? 
                AND (expires_at IS NULL OR expires_at > ?)
            ''', (key, datetime.now().timestamp()))
            
            row = cursor.fetchone()
            if row:
                return json.loads(row['metric_value'])
        return None
    
    def clear_expired_metrics(self):
        """Clean up expired cache entries."""
        with self.get_connection() as conn:
            conn.execute('''
                DELETE FROM metrics_cache 
                WHERE expires_at IS NOT NULL 
                AND expires_at <= ?
            ''', (datetime.now().timestamp(),))
    
    # ====================
    # LOG FILES METHODS
    # ====================
    
    def save_log_file_metadata(self, filename: str, file_size: int, 
                              row_count: int, columns: List[str],
                              user_id: str = 'default') -> int:
        """Save metadata about uploaded log files."""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                INSERT INTO log_files 
                (filename, file_size, row_count, columns, user_id)
                VALUES (?, ?, ?, ?, ?)
            ''', (filename, file_size, row_count, 
                  json.dumps(columns), user_id))
            return cursor.lastrowid
    
    def get_recent_log_files(self, limit: int = 10, 
                            user_id: str = 'default') -> List[Dict]:
        """Get recently uploaded log files."""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT * FROM log_files 
                WHERE user_id = ? 
                ORDER BY upload_time DESC 
                LIMIT ?
            ''', (user_id, limit))
            return [dict(row) for row in cursor.fetchall()]
    
    # ====================
    # RULE TEMPLATES METHODS
    # ====================
    
    def get_rule_templates(self, language: str = None, 
                          category: str = None) -> List[Dict]:
        """Get detection rule templates with optional filters."""
        with self.get_connection() as conn:
            query = 'SELECT * FROM rule_templates WHERE 1=1'
            params = []
            
            if language:
                query += ' AND language = ?'
                params.append(language)
            
            if category:
                query += ' AND category = ?'
                params.append(category)
            
            query += ' ORDER BY name'
            
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def add_rule_template(self, name: str, description: str, language: str, 
                         template: str, category: str = None, 
                         severity: str = None, tags: List[str] = None):
        """Add a new rule template."""
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO rule_templates 
                (name, description, language, template, category, severity, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (name, description, language, template, 
                  category, severity, json.dumps(tags or [])))
    
    # ====================
    # ANALYTICS METHODS (FIXED VERSION)
    # ====================
    
    def get_query_analytics(self, days: int = 30) -> Dict:
        """Get analytics about query executions with safe defaults."""
        try:
            with self.get_connection() as conn:
                # Most used queries - handle NULL values
                cursor = conn.execute('''
                    SELECT 
                        COALESCE(sq.name, 'Unknown') as name,
                        COALESCE(sq.query_language, 'Unknown') as query_language,
                        COUNT(qe.id) as execution_count,
                        AVG(COALESCE(qe.duration_ms, 0)) as avg_duration,
                        AVG(COALESCE(qe.result_count, 0)) as avg_results
                    FROM saved_queries sq
                    LEFT JOIN query_executions qe ON sq.id = qe.query_id
                    WHERE qe.execution_time >= datetime('now', ?) 
                       OR qe.execution_time IS NULL
                    GROUP BY sq.id
                    HAVING COUNT(qe.id) > 0
                    ORDER BY execution_count DESC
                    LIMIT 10
                ''', (f'-{days} days',))
                
                top_queries = []
                for row in cursor.fetchall():
                    top_queries.append({
                        'name': row['name'],
                        'query_language': row['query_language'],
                        'execution_count': row['execution_count'] or 0,
                        'avg_duration': row['avg_duration'] or 0,
                        'avg_results': row['avg_results'] or 0
                    })
                
                # Success rate
                cursor = conn.execute('''
                    SELECT 
                        SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                        COUNT(*) as total
                    FROM query_executions
                    WHERE execution_time >= datetime('now', ?)
                ''', (f'-{days} days',))
                
                row = cursor.fetchone()
                success_stats = {}
                if row:
                    total = row['total'] or 0
                    successful = row['successful'] or 0
                    success_rate = (successful * 100.0 / total) if total > 0 else 0
                    success_stats = {
                        'successful': successful,
                        'total': total,
                        'success_rate': success_rate
                    }
                else:
                    success_stats = {'successful': 0, 'total': 0, 'success_rate': 0}
                
                # Language distribution
                cursor = conn.execute('''
                    SELECT 
                        COALESCE(sq.query_language, 'Unknown') as query_language,
                        COUNT(*) as count
                    FROM query_executions qe
                    JOIN saved_queries sq ON qe.query_id = sq.id
                    WHERE qe.execution_time >= datetime('now', ?)
                    GROUP BY sq.query_language
                ''', (f'-{days} days',))
                
                language_dist = []
                for row in cursor.fetchall():
                    language_dist.append({
                        'query_language': row['query_language'],
                        'count': row['count'] or 0
                    })
                
                return {
                    'top_queries': top_queries,
                    'success_stats': success_stats,
                    'language_distribution': language_dist
                }
        except Exception as e:
            logger.error(f"Analytics fetch error: {e}")
            # Return safe empty structure
            return {
                'top_queries': [],
                'success_stats': {'successful': 0, 'total': 0, 'success_rate': 0},
                'language_distribution': []
            }


# Singleton instance
db_instance = SOCDatabase()
