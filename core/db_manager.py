import sqlite3
import datetime

class DBManager:
    def __init__(self, db_path='blackwall_logs.db'):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                type TEXT,  -- <--- ADD THIS COLUMN
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol INTEGER,
                description TEXT
            )
        ''')
        self.conn.commit()

    def log_alert(self, alert_data):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_type = "ERROR" if alert_data.get('severity') == 'High' else 'INFO'
        self.cursor.execute('''
            INSERT INTO alerts (timestamp, type, src_ip, dst_ip, src_port, dst_port, protocol, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            timestamp,
            alert_type,
            alert_data.get('src_ip', 'N/A'),
            alert_data.get('dst_ip', 'N/A'),
            alert_data.get('src_port', 0),
            alert_data.get('dst_port', 0),
            alert_data.get('protocol', 0),
            alert_data.get('description', 'Anomalous network packet detected.')
        ))
        self.conn.commit()

    def get_all_logs(self, limit=None):
        query = "SELECT * FROM alerts ORDER BY timestamp DESC"
        if limit:
            query += f" LIMIT {limit}"
        self.cursor.execute(query)
        return self.cursor.fetchall()
    
    def clear_all_logs(self):
        try:
            self.cursor.execute("DELETE FROM alerts")
            self.cursor.execute("DELETE FROM sqlite_sequence WHERE name='alerts'")
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error clearing logs: {e}")
            return False