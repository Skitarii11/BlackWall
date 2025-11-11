import datetime
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QLabel, QTableWidget, QTableWidgetItem, QStackedWidget,
                             QTextEdit, QHeaderView, QButtonGroup) # <-- Import QButtonGroup
from PyQt5.QtCore import pyqtSlot, QSize
from PyQt5.QtGui import QColor, QFont
import qtawesome as qta

from collections import Counter
from PyQt5.QtCore import QTimer
from ui.widgets.mpl_canvas import MplCanvas

from core.sniffer import SnifferThread
from core.feature_extractor import extract_features
from core.detection_engine import DetectionEngine
from core.db_manager import DBManager
from core.workers import CaptureWorker, TrainerWorker


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Blackwall IDS")
        self.setGeometry(100, 100, 1400, 900)

        # Initialize backend components
        self.sniffer_thread = SnifferThread()
        self.detection_engine = DetectionEngine('models/anomaly_detector.joblib')
        self.db_manager = DBManager()
        self.sniffer_thread.packet_captured.connect(self.process_packet)

        # Data for visualization
        self.protocol_counter = Counter()
        self.viz_update_timer = QTimer()
        self.viz_update_timer.setInterval(1000)
        self.viz_update_timer.timeout.connect(self.update_protocol_chart)

        self.init_ui()
        self.update_protocol_chart()

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # --- Sidebar ---
        sidebar_widget = QWidget()
        sidebar_widget.setObjectName("sidebar")
        sidebar_layout = QVBoxLayout(sidebar_widget)
        sidebar_widget.setFixedWidth(220)

        # --- CHANGE 1: Title Updated ---
        title = QLabel("BLACKWALL")
        title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        title.setObjectName("sidebar_title") # For potential future styling

        # --- Sidebar Buttons ---
        self.dashboard_btn = self.create_sidebar_button(" Dashboard", 'fa5s.tachometer-alt')
        self.live_alerts_btn = self.create_sidebar_button(" Live Alerts", 'fa5s.bell')
        self.logs_btn = self.create_sidebar_button(" Logs", 'fa5s.history')
        self.viz_btn = self.create_sidebar_button(" Visualization", 'fa5s.chart-bar')
        self.model_mgr_btn = self.create_sidebar_button(" Model Manager", 'fa5s.brain')

        self.dashboard_btn.setChecked(True)

        # --- CHANGE 2: Create an Exclusive Button Group ---
        self.nav_button_group = QButtonGroup()
        self.nav_button_group.setExclusive(True)
        self.nav_button_group.addButton(self.dashboard_btn)
        self.nav_button_group.addButton(self.live_alerts_btn)
        self.nav_button_group.addButton(self.logs_btn)
        self.nav_button_group.addButton(self.viz_btn)
        self.nav_button_group.addButton(self.model_mgr_btn)
        # --- End of Change 2 ---

        self.start_button = QPushButton("Start Monitoring")
        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.setEnabled(False)
        self.clear_logs_button = QPushButton("Clear All Logs")
        self.clear_logs_button.setObjectName("clear_logs_button")

        sidebar_layout.addWidget(title)
        sidebar_layout.addSpacing(20)
        sidebar_layout.addWidget(self.dashboard_btn)
        sidebar_layout.addWidget(self.live_alerts_btn)
        sidebar_layout.addWidget(self.logs_btn)
        sidebar_layout.addWidget(self.viz_btn)
        sidebar_layout.addWidget(self.model_mgr_btn)
        sidebar_layout.addStretch(1)
        sidebar_layout.addWidget(self.start_button)
        sidebar_layout.addWidget(self.stop_button)
        sidebar_layout.addWidget(self.clear_logs_button)

        # --- Main Content Area (No changes here) ---
        self.main_content = QStackedWidget()
        self.dashboard_page = QWidget()
        self.live_alerts_page = QWidget()
        self.logs_page = QWidget()
        self.viz_page = QWidget()
        self.model_page = QWidget()
        
        self.main_content.addWidget(self.dashboard_page)
        self.main_content.addWidget(self.live_alerts_page)
        self.main_content.addWidget(self.logs_page)
        self.main_content.addWidget(self.viz_page)
        self.main_content.addWidget(self.model_page)

        self.setup_dashboard_page()
        self.setup_live_alerts_page()
        self.setup_logs_page()
        self.setup_viz_page()
        self.setup_model_page()

        main_layout.addWidget(sidebar_widget)
        main_layout.addWidget(self.main_content)

        # --- Button Connections (No changes here) ---
        self.dashboard_btn.clicked.connect(lambda: self.main_content.setCurrentIndex(0))
        self.live_alerts_btn.clicked.connect(lambda: self.main_content.setCurrentIndex(1))
        self.logs_btn.clicked.connect(lambda: self.main_content.setCurrentIndex(2))
        self.viz_btn.clicked.connect(lambda: self.main_content.setCurrentIndex(3))
        self.model_mgr_btn.clicked.connect(lambda: self.main_content.setCurrentIndex(4))

        self.start_button.clicked.connect(self.start_monitoring)
        self.stop_button.clicked.connect(self.stop_monitoring)

    def create_sidebar_button(self, text, icon_name):
        button = QPushButton(text)
        button.setIcon(qta.icon(icon_name, color='#dcdcdc'))
        button.setIconSize(QSize(18, 18))
        button.setCheckable(True)
        return button

    # ... The rest of your code (setup_dashboard_page, start_monitoring, etc.) remains exactly the same.
    # No other changes are needed below this point.
    
    def setup_dashboard_page(self):
        layout = QVBoxLayout(self.dashboard_page)
        heading = QLabel("Dashboard")
        heading.setObjectName("heading")
        self.status_label = QLabel("Monitoring: Inactive")
        self.status_label.setFont(QFont("Segoe UI", 14))
        layout.addWidget(heading)
        layout.addWidget(self.status_label)
        layout.addStretch()

    def setup_live_alerts_page(self):
        layout = QVBoxLayout(self.live_alerts_page)
        heading = QLabel("Live Alerts")
        heading.setObjectName("heading")
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(5)
        self.alerts_table.setHorizontalHeaderLabels(["Time", "Source IP", "Destination IP", "Protocol", "Prediction"])
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(heading)
        layout.addWidget(self.alerts_table)

    def setup_logs_page(self):
        layout = QVBoxLayout(self.logs_page)
        heading = QLabel("Logs")
        heading.setObjectName("heading")
        self.logs_table = QTableWidget()
        self.logs_table.setColumnCount(8)
        self.logs_table.setHorizontalHeaderLabels(["ID", "Timestamp", "Source IP", "Dest IP", "Src Port", "Dst Port", "Protocol", "Description"])
        refresh_button = QPushButton("Refresh Logs")
        refresh_button.clicked.connect(self.populate_logs_table)
        layout.addWidget(heading)
        layout.addWidget(refresh_button)
        layout.addWidget(self.logs_table)
        self.populate_logs_table()

    def setup_viz_page(self):
        layout = QVBoxLayout(self.viz_page)
        heading = QLabel("Network Traffic")
        heading.setObjectName("heading")
        self.protocol_chart = MplCanvas(self, width=5, height=4, dpi=100)
        layout.addWidget(heading)
        layout.addWidget(self.protocol_chart)

    def setup_model_page(self):
        """This is your existing setup_model_tab logic, now for a page."""
        layout = QVBoxLayout(self.model_page)
        heading = QLabel("Model Manager")
        heading.setObjectName("heading")
        
        layout.addWidget(heading)
        layout.addWidget(QLabel("Step 1: Capture 'Normal' Traffic Baseline"))
        self.capture_button = QPushButton("Start 60-Second Capture")
        self.capture_button.clicked.connect(self.start_capture)
        
        layout.addWidget(QLabel("Step 2: Train New Model from Captured Data"))
        self.train_button = QPushButton("Train New Model")
        self.train_button.clicked.connect(self.start_training)
        self.train_button.setEnabled(False)

        layout.addWidget(QLabel("Status Log:"))
        self.model_status_log = QTextEdit()
        self.model_status_log.setReadOnly(True)
        
        layout.addWidget(self.capture_button)
        layout.addWidget(self.train_button)
        layout.addWidget(self.model_status_log)
        self.captured_pcap_path = ""

    def start_monitoring(self):
        if not self.sniffer_thread.isRunning():
            self.sniffer_thread.start()
            self.status_label.setText("Monitoring: Active")
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.protocol_counter.clear()
            self.viz_update_timer.start()
            print("Monitoring started.")

    def stop_monitoring(self):
        if self.sniffer_thread.isRunning():
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()
            self.status_label.setText("Monitoring: Inactive")
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.viz_update_timer.stop()
            print("Monitoring stopped.")

    @pyqtSlot(object)
    def process_packet(self, packet):
        proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        if packet.haslayer("IP"):
            protocol_num = packet["IP"].proto
            if protocol_num in proto_map:
                self.protocol_counter[proto_map[protocol_num]] += 1
        
        numerical_features, log_features = extract_features(packet)
        if numerical_features:
            is_anomaly = self.detection_engine.predict(numerical_features)
            if is_anomaly:
                log_features['description'] = "Anomalous packet structure detected."
                log_features['severity'] = "High"
                self.add_alert_to_ui(log_features)
                self.db_manager.log_alert(log_features)

    def add_alert_to_ui(self, log_features):
        self.alerts_table.insertRow(0)
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        
        time_item = QTableWidgetItem(timestamp)
        src_ip_item = QTableWidgetItem(log_features.get('src_ip', 'N/A'))
        dst_ip_item = QTableWidgetItem(log_features.get('dst_ip', 'N/A'))
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        proto_item = QTableWidgetItem(proto_map.get(log_features.get('protocol'), 'Other'))
        pred_item = QTableWidgetItem("Attack")

        pred_item.setForeground(QColor("#e74c3c"))
        pred_item.setFont(QFont("Segoe UI", 10, QFont.Bold))

        self.alerts_table.setItem(0, 0, time_item)
        self.alerts_table.setItem(0, 1, src_ip_item)
        self.alerts_table.setItem(0, 2, dst_ip_item)
        self.alerts_table.setItem(0, 3, proto_item)
        self.alerts_table.setItem(0, 4, pred_item)

    def populate_logs_table(self):
        self.logs_table.setRowCount(0)
        logs = self.db_manager.get_all_logs()
        for row_index, row_data in enumerate(logs):
            self.logs_table.insertRow(row_index)
            for col_index, cell_data in enumerate(row_data):
                self.logs_table.setItem(row_index, col_index, QTableWidgetItem(str(cell_data)))
        self.logs_table.resizeColumnsToContents()

    def update_protocol_chart(self):
        if not self.protocol_counter:
            labels = ['TCP', 'UDP', 'ICMP']
            counts = [0, 0, 0]
        else:
            labels = self.protocol_counter.keys()
            counts = self.protocol_counter.values()

        ax = self.protocol_chart.axes
        ax.clear()
        ax.bar(labels, counts, color='#e74c3c')
        ax.set_title("Live Network Protocol Distribution", color='#dcdcdc')
        ax.set_ylabel("Packet Count", color='#dcdcdc')
        ax.tick_params(axis='x', colors='#dcdcdc')
        ax.tick_params(axis='y', colors='#dcdcdc')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['bottom'].set_color('#3a3b4f')
        ax.spines['left'].set_color('#3a3b4f')
        self.protocol_chart.figure.set_facecolor('#1e1e2e')
        ax.set_facecolor('#27293d')
        self.protocol_chart.draw()

    def log_model_status(self, message):
        self.model_status_log.append(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {message}")

    def start_capture(self):
        if hasattr(self, 'capture_worker') and self.capture_worker.isRunning():
            return
        self.capture_button.setText("Capturing... (Click to Cancel)")
        self.train_button.setEnabled(False)
        self.capture_worker = CaptureWorker(duration_sec=60)
        self.capture_worker.progress.connect(self.log_model_status)
        self.capture_worker.finished.connect(self.on_capture_finished)
        self.capture_button.clicked.disconnect()
        self.capture_button.clicked.connect(self.capture_worker.stop)
        self.capture_worker.start()

    def on_capture_finished(self, pcap_path):
        self.captured_pcap_path = pcap_path
        if pcap_path:
            self.train_button.setEnabled(True)
        self.capture_button.setText("Start 60-Second Capture")
        self.capture_button.clicked.disconnect()
        self.capture_button.clicked.connect(self.start_capture)

    def start_training(self):
        if not self.captured_pcap_path:
            self.log_model_status("Error: No pcap file captured yet.")
            return
        self.train_button.setEnabled(False)
        self.capture_button.setEnabled(False)
        self.trainer_worker = TrainerWorker(self.captured_pcap_path)
        self.trainer_worker.progress.connect(self.log_model_status)
        self.trainer_worker.finished.connect(self.on_training_finished)
        self.trainer_worker.start()

    def on_training_finished(self, model_path):
        if model_path:
            self.log_model_status("Reloading detection engine with new model...")
            self.detection_engine = DetectionEngine(model_path)
            self.log_model_status("Engine reloaded. Blackwall is now using the new model.")
        self.train_button.setEnabled(True)
        self.capture_button.setEnabled(True)

    def closeEvent(self, event):
        self.stop_monitoring()
        event.accept()