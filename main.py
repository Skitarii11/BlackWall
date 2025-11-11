import sys
import os
from PyQt5.QtWidgets import QApplication, QMessageBox
from ui.main_window import MainWindow

def check_privileges():
    # ... (this function remains the same)
    try:
        is_admin = (os.getuid() == 0)
    except AttributeError:
        import ctypes
        is_admin = (ctypes.windll.shell32.IsUserAnAdmin() != 0)
    return is_admin

if __name__ == '__main__':
    app = QApplication(sys.argv)

    # --- LOAD THE STYLESHEET ---
    try:
        with open('style.qss', 'r') as f:
            stylesheet = f.read()
        app.setStyleSheet(stylesheet)
    except FileNotFoundError:
        print("Warning: style.qss not found. Using default styles.")
    # --- END OF STYLESHEET LOADING ---

    if not check_privileges():
        QMessageBox.critical(
            None, 
            "Administrator Privileges Required",
            "Please restart with administrator/root privileges."
        )
        sys.exit(1)

    main_win = MainWindow()
    main_win.show()
    sys.exit(app.exec_())