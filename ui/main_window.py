import os
import datetime
import numpy as np
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QLabel, QTableWidget, QTableWidgetItem, QStackedWidget,
                             QTextEdit, QHeaderView, QButtonGroup, QMessageBox)
from PyQt5.QtCore import pyqtSlot, QSize, Qt, QPoint # <-- Import QPoint
from PyQt5.QtGui import QColor, QFont, QPen, QIcon

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
        
        # --- CHANGE 1: Go Frameless ---
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground) # For rounded corners later if desired
        # --- End of Change 1 ---

        self.setWindowIcon(QIcon('assets/icon.png'))
        self.setWindowTitle("Blackwall IDS")
        self.setGeometry(100, 100, 1400, 900)
        
        # Backend components...
        self.sniffer_thread = SnifferThread()
        self.detection_engine = DetectionEngine('models/anomaly_detector.joblib')
        self.db_manager = DBManager()
        self.sniffer_thread.packet_captured.connect(self.process_packet)
        
        # Data and timers...
        self.protocol_counter = Counter()
        self.viz_update_timer = QTimer()
        self.viz_update_timer.setInterval(1000)
        self.viz_update_timer.timeout.connect(self.update_charts)
        
        self.packet_count = 0
        self.attack_count = 0
        self.dashboard_traffic_data = []

        self.init_ui()
        self.update_charts()

        # --- CHANGE 2: Variable for dragging the window ---
        self._drag_pos = QPoint()

    def init_ui(self):
        # Create a central container widget with a black border
        self.container = QWidget()
        self.container.setObjectName("container")
        self.container.setStyleSheet("#container { background-color: #161625; border: 1px solid #000000; }") # Black border
        self.setCentralWidget(self.container)

        # Main layout for the container
        container_layout = QVBoxLayout(self.container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setSpacing(0)

        # --- CHANGE 3: Create and add the custom title bar ---
        title_bar = self.create_title_bar()
        container_layout.addWidget(title_bar)
        # --- End of Change 3 ---

        # The rest of the layout is now inside another widget
        content_widget = QWidget()
        main_layout = QHBoxLayout(content_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Sidebar... (no changes here)
        sidebar_widget = QWidget()
        sidebar_widget.setObjectName("sidebar")
        sidebar_layout = QVBoxLayout(sidebar_widget)
        sidebar_widget.setFixedWidth(220)
        title = QLabel("BLACKWALL")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        title.setObjectName("sidebar_title")
        self.dashboard_btn = self.create_sidebar_button(" Dashboard", 'fa5s.tachometer-alt')
        self.live_alerts_btn = self.create_sidebar_button(" Live Alerts", 'fa5s.bell')
        self.logs_btn = self.create_sidebar_button(" Logs", 'fa5s.history')
        self.viz_btn = self.create_sidebar_button(" Visualization", 'fa5s.chart-bar')
        self.model_mgr_btn = self.create_sidebar_button(" Model Manager", 'fa5s.brain')
        self.dashboard_btn.setChecked(True)
        self.nav_button_group = QButtonGroup()
        self.nav_button_group.setExclusive(True)
        for btn in [self.dashboard_btn, self.live_alerts_btn, self.logs_btn, self.viz_btn, self.model_mgr_btn]:
            self.nav_button_group.addButton(btn)
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
        
        # Main content area... (no changes here)
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

        # Add the main content widget to the container layout
        container_layout.addWidget(content_widget)

        # Button connections... (no changes here)
        self.dashboard_btn.clicked.connect(lambda: self.main_content.setCurrentIndex(0))
        self.live_alerts_btn.clicked.connect(lambda: self.main_content.setCurrentIndex(1))
        self.logs_btn.clicked.connect(lambda: self.main_content.setCurrentIndex(2))
        self.viz_btn.clicked.connect(lambda: self.main_content.setCurrentIndex(3))
        self.model_mgr_btn.clicked.connect(lambda: self.main_content.setCurrentIndex(4))
        self.start_button.clicked.connect(self.start_monitoring)
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.clear_logs_button.clicked.connect(self.clear_logs)
        self.status_icon_label.setPixmap(qta.icon('fa5s.times-circle', color='#e74c3c').pixmap(QSize(24, 24)))

    # --- CHANGE 4: New method to create the title bar ---
    def create_title_bar(self):
        title_bar = QWidget()
        title_bar.setObjectName("title_bar")
        title_bar_layout = QHBoxLayout(title_bar)
        title_bar_layout.setContentsMargins(0, 0, 0, 0)

        # Icon and Title
        icon_label = QLabel()
        icon_label.setPixmap(QIcon('assets/icon.png').pixmap(QSize(16, 16)))
        title_label = QLabel("Blackwall IDS")
        
        title_bar_layout.addWidget(icon_label)
        title_bar_layout.addWidget(title_label)
        title_bar_layout.addStretch()

        # Window control buttons
        minimize_button = QPushButton(qta.icon('fa5s.window-minimize', color='white'), "")
        maximize_button = QPushButton(qta.icon('fa5s.window-maximize', color='white'), "")
        close_button = QPushButton(qta.icon('fa5s.times', color='white'), "")
        close_button.setObjectName("close_button") # For special hover style

        minimize_button.clicked.connect(self.showMinimized)
        maximize_button.clicked.connect(self.toggle_maximize)
        close_button.clicked.connect(self.close)

        title_bar_layout.addWidget(minimize_button)
        title_bar_layout.addWidget(maximize_button)
        title_bar_layout.addWidget(close_button)

        return title_bar

    def toggle_maximize(self):
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    # --- CHANGE 5: New methods to handle window dragging ---
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_pos = event.globalPos() - self.pos()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.LeftButton:
            self.move(event.globalPos() - self._drag_pos)
            event.accept()
    # --- End of Change 5 ---

    # ... The rest of your code (create_sidebar_button, all setup_..._page methods, etc.) remains exactly the same.
    def create_sidebar_button(self, text, icon_name):
        button = QPushButton(text)
        button.setIcon(qta.icon(icon_name, color='#dcdcdc'))
        button.setIconSize(QSize(18, 18))
        button.setCheckable(True)
        return button
    
    def setup_dashboard_page(self):
        layout = QVBoxLayout(self.dashboard_page)
        heading = QLabel("Dashboard")
        heading.setObjectName("heading")
        layout.addWidget(heading)
        status_layout = QHBoxLayout()
        self.status_icon_label = QLabel() 
        self.status_text_label = QLabel("Monitoring")
        self.status_text_label.setFont(QFont("Segoe UI", 14))
        status_layout.addWidget(self.status_icon_label)
        status_layout.addWidget(self.status_text_label)
        status_layout.addStretch()
        layout.addLayout(status_layout)
        top_layout = QHBoxLayout()
        stats_widget = QWidget()
        stats_layout = QVBoxLayout(stats_widget)
        self.packets_label = QLabel("0")
        self.packets_label.setObjectName("stat_value")
        self.attacks_label = QLabel("0")
        self.attacks_label.setObjectName("stat_value")
        stats_layout.addWidget(QLabel("Total Packets Monitored", objectName="stat_label"))
        stats_layout.addWidget(self.packets_label)
        stats_layout.addSpacing(20)
        stats_layout.addWidget(QLabel("Attacks Detected", objectName="stat_label"))
        stats_layout.addWidget(self.attacks_label)
        stats_layout.addStretch()
        self.dashboard_chart = MplCanvas(self, width=5, height=2, dpi=100)
        top_layout.addWidget(stats_widget)
        top_layout.addWidget(self.dashboard_chart, stretch=1)
        layout.addLayout(top_layout)
        bottom_layout = QHBoxLayout()
        self.dashboard_alerts_table = QTableWidget()
        self.dashboard_alerts_table.setColumnCount(3)
        self.dashboard_alerts_table.setHorizontalHeaderLabels(["Time", "Source IP", "Prediction"])
        self.dashboard_alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.dashboard_alerts_table.verticalHeader().setVisible(False)
        self.dashboard_logs_table = QTableWidget()
        self.dashboard_logs_table.setColumnCount(3)
        self.dashboard_logs_table.setHorizontalHeaderLabels(["Timestamp", "Type", "Message"])
        self.dashboard_logs_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.dashboard_logs_table.verticalHeader().setVisible(False)
        bottom_layout.addWidget(self.dashboard_alerts_table)
        bottom_layout.addWidget(self.dashboard_logs_table)
        layout.addLayout(bottom_layout)

    def setup_live_alerts_page(self):
        layout = QVBoxLayout(self.live_alerts_page)
        heading = QLabel("Live Alerts")
        heading.setObjectName("heading")
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(5)
        self.alerts_table.setHorizontalHeaderLabels(["Time", "Source IP", "Destination IP", "Protocol", "Prediction"])
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.alerts_table.verticalHeader().setVisible(False)
        layout.addWidget(heading)
        layout.addWidget(self.alerts_table)

    def setup_logs_page(self):
        layout = QVBoxLayout(self.logs_page)
        heading = QLabel("Logs")
        heading.setObjectName("heading")
        self.logs_table = QTableWidget()
        self.logs_table.setColumnCount(4)
        self.logs_table.setHorizontalHeaderLabels(["ID", "Timestamp", "Type", "Message"])
        self.logs_table.setAlternatingRowColors(True)
        self.logs_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.logs_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.logs_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.logs_table.verticalHeader().setVisible(False)
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
        layout.addStretch(1)
        layout.addWidget(self.protocol_chart)
        layout.addStretch(1)

    def setup_model_page(self):
        layout = QVBoxLayout(self.model_page)
        heading = QLabel("Model Manager")
        heading.setObjectName("heading")
        layout.addWidget(heading)
        layout.addWidget(QLabel("Step 1: Add to Your 'Normal' Traffic Baseline"))
        self.capture_button = QPushButton("Start 60-Second Capture")
        self.capture_button.clicked.connect(self.start_capture)
        layout.addWidget(QLabel("Step 2: Retrain Model on All Captured Data"))
        self.train_button = QPushButton("Train New Model")
        self.train_button.clicked.connect(self.start_training)
        self.train_button.setEnabled(os.path.exists("normal_traffic.pcap"))
        layout.addWidget(QLabel("Status Log:"))
        self.model_status_log = QTextEdit()
        self.model_status_log.setReadOnly(True)
        layout.addWidget(self.capture_button)
        layout.addWidget(self.train_button)
        layout.addWidget(self.model_status_log)
        self.captured_pcap_path = "normal_traffic.pcap"
    
    def clear_logs(self):
        reply = QMessageBox.question(self, 'Confirm Clear', 
                                     "Are you sure you want to delete all log entries? This action cannot be undone.",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            if self.db_manager.clear_all_logs():
                self.populate_logs_table()
                self.update_dashboard_tables()
                print("Logs cleared successfully.")
            else:
                QMessageBox.critical(self, "Error", "Failed to clear logs from the database.")

    def start_monitoring(self):
        if not self.sniffer_thread.isRunning():
            self.packet_count = 0
            self.attack_count = 0
            self.dashboard_traffic_data = []
            self.sniffer_thread.start()
            self.status_icon_label.setPixmap(qta.icon('fa5s.check-circle', color='green').pixmap(QSize(24, 24)))
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.protocol_counter.clear()
            self.viz_update_timer.start()
            print("Monitoring started.")

    def stop_monitoring(self):
        if self.sniffer_thread.isRunning():
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()
            self.status_icon_label.setPixmap(qta.icon('fa5s.times-circle', color='#e74c3c').pixmap(QSize(24, 24)))
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.viz_update_timer.stop()
            print("Monitoring stopped.")

    @pyqtSlot(object)
    def process_packet(self, packet):
        self.packet_count += 1
        proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        if packet.haslayer("IP"):
            protocol_num = packet["IP"].proto
            if protocol_num in proto_map:
                self.protocol_counter[proto_map[protocol_num]] += 1
        
        numerical_features, log_features = extract_features(packet)
        if numerical_features:
            is_anomaly = self.detection_engine.predict(numerical_features)
            if is_anomaly:
                self.attack_count += 1
                log_features['description'] = "Anomalous packet structure detected."
                log_features['severity'] = "High"
                self.add_alert_to_ui(log_features)
                self.db_manager.log_alert(log_features)
                self.update_dashboard_tables()
        self.update_dashboard_stats()

    def update_dashboard_stats(self):
        self.packets_label.setText(str(self.packet_count))
        self.attacks_label.setText(str(self.attack_count))

    def update_dashboard_tables(self):
        self.dashboard_alerts_table.setRowCount(0)
        alerts = self.db_manager.get_all_logs(limit=5)
        attack_count = 0
        for data in alerts:
            if data[2] == "ERROR" and attack_count < 5:
                self.dashboard_alerts_table.insertRow(attack_count)
                self.dashboard_alerts_table.setItem(attack_count, 0, QTableWidgetItem(data[1].split(" ")[1]))
                self.dashboard_alerts_table.setItem(attack_count, 1, QTableWidgetItem(data[3]))
                pred_item = QTableWidgetItem("Attack")
                pred_item.setForeground(QColor("#e74c3c"))
                self.dashboard_alerts_table.setItem(attack_count, 2, pred_item)
                attack_count += 1

        self.dashboard_logs_table.setRowCount(0)
        logs = self.db_manager.get_all_logs(limit=5)
        for row, data in enumerate(logs):
            self.dashboard_logs_table.insertRow(row)
            self.dashboard_logs_table.setItem(row, 0, QTableWidgetItem(data[1]))
            type_item = QTableWidgetItem(data[2])
            if data[2] == "ERROR":
                type_item.setForeground(QColor("#e74c3c"))
            self.dashboard_logs_table.setItem(row, 1, type_item)
            self.dashboard_logs_table.setItem(row, 2, QTableWidgetItem(data[8]))

    def update_charts(self):
        self.update_protocol_chart()
        current_total = sum(self.protocol_counter.values())
        self.dashboard_traffic_data.append(current_total)
        if len(self.dashboard_traffic_data) > 30:
            self.dashboard_traffic_data.pop(0)
        self.update_line_chart(self.dashboard_chart, self.dashboard_traffic_data, "Live Traffic")
        self.protocol_counter.clear()

    def update_protocol_chart(self):
        ax = self.protocol_chart.axes
        ax.clear()
        protocols = ['TCP', 'UDP', 'ICMP']
        colors = ['#3498db', '#2ecc71', '#f1c40f']
        counts = [self.protocol_counter.get(p, 0) for p in protocols]
        ax.bar(protocols, counts, color=colors)
        ax.set_title("Live Network Protocol Distribution", color='#dcdcdc')
        ax.set_ylabel("Packet Count / sec", color='#dcdcdc')
        self.style_chart_ax(ax)
        self.protocol_chart.draw()

    def update_line_chart(self, chart_widget, data, title):
        ax = chart_widget.axes
        ax.clear()
        ax.plot(data, color='#e74c3c', linewidth=2)
        ax.fill_between(range(len(data)), data, color='#e74c3c', alpha=0.3)
        ax.set_title(title, color='#dcdcdc')
        self.style_chart_ax(ax)
        ax.set_yticklabels([])
        ax.set_xticklabels([])
        chart_widget.draw()

    def style_chart_ax(self, ax):
        ax.tick_params(axis='x', colors='#dcdcdc')
        ax.tick_params(axis='y', colors='#dcdcdc')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['bottom'].set_color('#3a3b4f')
        ax.spines['left'].set_color('#3a3b4f')
        ax.grid(True, which='both', linestyle='--', linewidth=0.5, color='#3a3b4f')
        ax.set_facecolor('#1e1e2e')
        ax.figure.set_facecolor('#161625')
        
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
        for row, data in enumerate(logs):
            self.logs_table.insertRow(row)
            self.logs_table.setItem(row, 0, QTableWidgetItem(str(data[0])))
            self.logs_table.setItem(row, 1, QTableWidgetItem(data[1]))
            log_type = data[2]
            type_item = QTableWidgetItem(log_type)
            if log_type == "ERROR":
                type_item.setForeground(QColor("#e74c3c"))
                type_item.setFont(QFont("Segoe UI", 10, QFont.Bold))
            self.logs_table.setItem(row, 2, type_item)
            message = f"{data[8]} from {data[3]}:{data[5]} to {data[4]}:{data[6]}"
            self.logs_table.setItem(row, 3, QTableWidgetItem(message))
        self.update_dashboard_tables()
    
    def log_model_status(self, message): self.model_status_log.append(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {message}")
    def start_capture(self):
        if hasattr(self, 'capture_worker') and self.capture_worker.isRunning(): return
        self.capture_button.setText("Capturing... (Click to Cancel)")
        self.train_button.setEnabled(False)
        self.capture_worker = CaptureWorker(duration_sec=60)
        self.capture_worker.progress.connect(self.log_model_status)
        self.capture_worker.finished.connect(self.on_capture_finished)
        self.capture_button.clicked.disconnect()
        self.capture_button.clicked.connect(self.capture_worker.stop)
        self.capture_worker.start()
    def on_capture_finished(self, pcap_path):
        self.captured_pcap_path = "normal_traffic.pcap"
        if pcap_path: self.train_button.setEnabled(True)
        self.capture_button.setText("Start 60-Second Capture")
        self.capture_button.clicked.disconnect()
        self.capture_button.clicked.connect(self.start_capture)
    def start_training(self):
        if not self.captured_pcap_path or not os.path.exists(self.captured_pcap_path): self.log_model_status("Error: No pcap file captured yet."); return
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
            self.log_model_status("Engine reloaded.")
        self.train_button.setEnabled(True)
        self.capture_button.setEnabled(True)

    def closeEvent(self, event):
        self.stop_monitoring()
        event.accept()