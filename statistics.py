from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel

class StatisticsTab(QWidget):
    def __init__(self, antivirus):
        super().__init__()
        self.antivirus = antivirus
        layout = QVBoxLayout()
        self.label = QLabel("Статистика: Сканов - 0, Вирусов - 0")
        layout.addWidget(self.label)
        self.setLayout(layout)
        # Placeholder: Update this with real statistics from antivirus.scan_history if needed