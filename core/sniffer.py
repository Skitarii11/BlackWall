from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import sniff, Packet

class SnifferThread(QThread):
    packet_captured = pyqtSignal(Packet)

    def __init__(self, interface=None):
        super().__init__()
        self.interface = interface
        self.running = False

    def run(self):
        self.running = True
        sniff(iface=self.interface, prn=self.process_packet, stop_filter=lambda p: not self.running)

    def process_packet(self, packet):
        if self.running:
            self.packet_captured.emit(packet)

    def stop(self):
        self.running = False