def apply_theme(widget):
    widget.setStyleSheet("""
        QWidget {
            background-color: #1A2330;
            color: #FFFFFF;
            font-family: Roboto, sans-serif;
            font-size: 12pt;
        }
        QPushButton {
            background-color: #00CC00;
            color: #FFFFFF;
            padding: 10px;
            border-radius: 5px;
        }
        QPushButton:hover {
            background-color: #009900;
        }
        QProgressBar {
            background-color: #333333;
            border-radius: 5px;
            text-align: center;
        }
        QProgressBar::chunk {
            background-color: #00CC00;
            border-radius: 5px;
        }
        QTableWidget {
            background-color: #2A2F40;
            alternate-background-color: #333333;
        }
        QLabel {
            color: #A0A0A0;
        }
    """)