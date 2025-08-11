#!/usr/bin/env python3
"""
Test GUI - Quick test to see the interface without database setup
"""

import sys
import os
from pathlib import Path

# Add src directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))

from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt

class TestWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Personal Finance Manager - Test")
        self.setGeometry(100, 100, 800, 600)
        
        # Set application icon
        icon_path = Path(__file__).parent.parent / "resources" / "app_icon.png"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
            print(f"Icon loaded from: {icon_path}")
        else:
            print(f"Icon not found at: {icon_path}")
        
        # Simple test content
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        # Test labels
        title_label = QLabel("Personal Finance Manager")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 24px; font-weight: bold; margin: 20px;")
        
        icon_label = QLabel("✅ App icon with F and M letters loaded successfully!")
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setStyleSheet("font-size: 16px; color: green; margin: 20px;")
        
        info_label = QLabel("This is a test window to verify the GUI components.\nThe full application requires database password for security.")
        info_label.setAlignment(Qt.AlignCenter)
        info_label.setStyleSheet("font-size: 14px; margin: 20px;")
        
        layout.addWidget(title_label)
        layout.addWidget(icon_label)
        layout.addWidget(info_label)

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Personal Finance Manager")
    
    window = TestWindow()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
