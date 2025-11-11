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
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol INTEGER,
                severity TEXT,
                description TEXT
            )
        ''')
        self.conn.commit()

    def log_alert(self, alert_data):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute('''
            INSERT INTO alerts (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, severity, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            timestamp,
            alert_data.get('src_ip', 'N/A'),
            alert_data.get('dst_ip', 'N/A'),
            alert_data.get('src_port', 0),
            alert_data.get('dst_port', 0),
            alert_data.get('protocol', 0),
            alert_data.get('severity', 'Medium'),
            alert_data.get('description', 'Anomalous network packet detected.')
        ))
        self.conn.commit()

    def get_all_logs(self):
        self.cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
        return self.cursor.fetchall()