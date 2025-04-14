import os
import hashlib
import json
import time
import logging
import sqlite3
import sys
import psutil
import shutil
import platform
import asyncio
import aiohttp
import yara
import lief
import numpy as np
try:
    import tensorflow as tf
except ImportError:
    tf = None
    logging.warning("TensorFlow не доступен. Функции ML отключены.")
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from threading import Lock
import threading
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QProgressBar, QLabel, QFileDialog,
    QSystemTrayIcon, QMenu, QAction, QListWidget, QListWidgetItem, QStackedWidget,
    QComboBox, QTextEdit, QCheckBox
)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer, Qt, QRunnable, QThreadPool, QObject
from PyQt5.QtGui import QIcon
import re
from plyer import notification
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pefile
import socket
from urllib.parse import urlparse
import glob

# Подавление логов TensorFlow
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('forever_ai.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

# Константы
SYSTEM = platform.system()
QUARANTINE_DIR = os.path.expanduser("~/карантин" if SYSTEM != "Windows" else "~\\карантин")
SIGNATURE_DB = "сигнатуры_вирусов.json"
HISTORY_FILE = "история_сканирования.json"
CACHE_DB = "кэш_антивируса.db"
YARA_RULES = "правила_yara.yar"
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
MAX_FILE_SIZE = 200 * 1024 * 1024  # 200 MB
CHUNK_SIZE = 16384
ICON_PATH = "icon.ico"
MAX_CONCURRENT_SCANS = 4
TEMP_EXTENSIONS = {'.tmp', '.TMP', '.temp', '.bak', '.crdownload'}

class FileScanWorker(QRunnable):
    def __init__(self, antivirus, file_path, scan_depth, signals):
        super().__init__()
        self.antivirus = antivirus
        self.file_path = file_path
        self.scan_depth = scan_depth
        self.signals = signals
        self.setAutoDelete(True)

    def run(self):
        try:
            if not os.path.isfile(self.file_path) or not os.access(self.file_path, os.R_OK):
                self.signals.result_signal.emit({"путь": self.file_path, "статус": "Пропущен", "детали": "Нет доступа", "оценка": 0.0, "уровень_угрозы": "Нет"})
                return
            if os.path.getsize(self.file_path) > MAX_FILE_SIZE:
                self.signals.result_signal.emit({"путь": self.file_path, "статус": "Пропущен", "детали": "Слишком большой", "оценка": 0.0, "уровень_угрозы": "Нет"})
                return
            is_infected, details, score = self.antivirus.scan_file(self.file_path, self.scan_depth)
            result = {
                "путь": self.file_path,
                "статус": "Вирус" if is_infected else "Чисто",
                "детали": details,
                "оценка": score,
                "уровень_угрозы": self.antivirus.get_threat_level(score)
            }
            self.signals.result_signal.emit(result)
        except Exception as e:
            logging.error(f"Ошибка сканирования {self.file_path}: {e}")
            self.signals.result_signal.emit({"путь": self.file_path, "статус": "Ошибка", "детали": str(e), "оценка": 0.0, "уровень_угрозы": "Нет"})

class WorkerSignals(QObject):
    result_signal = pyqtSignal(dict)

class ScanWorker(QThread):
    result_signal = pyqtSignal(dict)
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal()
    current_file_signal = pyqtSignal(str)

    def __init__(self, antivirus, target, scan_depth):
        super().__init__()
        self.antivirus = antivirus
        self.target = target
        self.scan_depth = scan_depth
        self._running = True
        self.thread_pool = QThreadPool()
        self.thread_pool.setMaxThreadCount(MAX_CONCURRENT_SCANS)
        self.completed = 0
        self.total = 0
        self.scan_queue = Queue()
        self.lock = Lock()

    def run(self):
        try:
            if os.path.isdir(self.target):
                files = [os.path.join(dp, f) for dp, _, filenames in os.walk(self.target)
                         for f in filenames if not f.startswith('.') and os.path.splitext(f)[1].lower() not in TEMP_EXTENSIONS]
                self.total = len(files)
                for file_path in files:
                    if not self._running:
                        break
                    self.scan_queue.put(file_path)
                while not self.scan_queue.empty() and self._running:
                    if psutil.cpu_percent() > 80:
                        time.sleep(1)
                        continue
                    file_path = self.scan_queue.get()
                    self.current_file_signal.emit(file_path)
                    signals = WorkerSignals()
                    worker = FileScanWorker(self.antivirus, file_path, self.scan_depth, signals)
                    signals.result_signal.connect(self.result_signal.emit)
                    self.thread_pool.start(worker)
                    with self.lock:
                        self.completed += 1
                    self.progress_signal.emit(int(self.completed / self.total * 100) if self.total > 0 else 100)
                self.thread_pool.waitForDone()
            else:
                is_infected, details, score = self.antivirus.scan_file(self.target, self.scan_depth)
                result = {
                    "путь": self.target,
                    "статус": "Вирус" if is_infected else "Чисто",
                    "детали": details,
                    "оценка": score,
                    "уровень_угрозы": self.antivirus.get_threat_level(score)
                }
                self.result_signal.emit(result)
                self.progress_signal.emit(100)
            self.finished_signal.emit()
        except Exception as e:
            logging.error(f"Ошибка сканирования: {e}")
            self.result_signal.emit({"путь": self.target, "статус": "Ошибка", "детали": str(e), "оценка": 0.0, "уровень_угрозы": "Нет"})
            self.finished_signal.emit()

    def stop(self):
        self._running = False
        self.thread_pool.clear()

class NetworkMonitor(QThread):
    threat_signal = pyqtSignal(dict)

    def __init__(self, antivirus):
        super().__init__()
        self.antivirus = antivirus
        self.running = True

    def run(self):
        while self.running:
            if psutil.cpu_percent() > 80:
                time.sleep(5)
                continue
            is_threat, details = self.antivirus.monitor_network_connections()
            if is_threat:
                self.threat_signal.emit({"тип": "Сеть", "детали": details})
            is_unauthorized, access_details = self.antivirus.check_unauthorized_access()
            if is_unauthorized:
                self.threat_signal.emit({"тип": "Доступ", "детали": access_details})
            time.sleep(5)

    def stop(self):
        self.running = False

class BrowserMonitor(QThread):
    threat_signal = pyqtSignal(dict)

    def __init__(self, antivirus):
        super().__init__()
        self.antivirus = antivirus
        self.running = True

    def run(self):
        while self.running:
            if psutil.cpu_percent() > 80:
                time.sleep(5)
                continue
            threats = self.antivirus.scan_browser_extensions()
            for threat in threats:
                self.threat_signal.emit({"тип": "Браузер", "детали": threat})
            time.sleep(60)

    def stop(self):
        self.running = False

class RealTimeMonitor(FileSystemEventHandler):
    def __init__(self, antivirus):
        super().__init__()
        self.antivirus = antivirus
        self.download_dirs = [os.path.expanduser("~/Downloads")]

    def on_created(self, event):
        if not event.is_directory and os.path.splitext(event.src_path)[1].lower() not in TEMP_EXTENSIONS:
            file_path = event.src_path
            if any(file_path.startswith(d) for d in self.download_dirs):
                is_infected, details, score = self.antivirus.scan_downloaded_file(file_path)
                if is_infected:
                    notification.notify(
                        title="FOREVER AI: Загрузка",
                        message=f"Вирус в загрузке: {os.path.basename(file_path)}"
                    )
                    self.antivirus.quarantine_file(file_path)
            is_infected, details, score = self.antivirus.scan_file(file_path, "Быстрое")
            if is_infected:
                notification.notify(
                    title="FOREVER AI",
                    message=f"Вирус: {os.path.basename(file_path)}"
                )

    def on_modified(self, event):
        if not event.is_directory and os.path.splitext(event.src_path)[1].lower() not in TEMP_EXTENSIONS:
            file_path = event.src_path
            if file_path.endswith((".exe", ".py", ".sh")):
                allow, details = self.antivirus.control_program_execution(file_path)
                if not allow:
                    notification.notify(
                        title="FOREVER AI: Запуск",
                        message="Запуск заблокирован"
                    )

class SuperAntivirus:
    def __init__(self):
        self.signature_db = SIGNATURE_DB
        self.quarantine_folder = QUARANTINE_DIR
        self.history_file = HISTORY_FILE
        self.cache_db = CACHE_DB
        self.yara_rules = YARA_RULES
        os.makedirs(self.quarantine_folder, exist_ok=True)
        self.signatures = self.load_signatures()
        self.scan_history = self.load_history()
        self.db_conn = self.init_cache()
        self.yara_compiled = self.compile_yara_rules()
        self.ml_model = self.load_ml_model()
        self.ml_available = self.ml_model is not None
        self.executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_SCANS)
        self.blocklist = self.load_blocklist()
        self.malicious_ips = set(["93.184.216.34"])
        self.network_monitor_active = True
        self.system_monitor_active = True
        logging.info(f"Python version: {sys.version}")
        if tf is not None:
            logging.info(f"TensorFlow version: {tf.__version__}")

    def init_cache(self):
        try:
            conn = sqlite3.connect(self.cache_db, check_same_thread=False)
            conn.execute("CREATE TABLE IF NOT EXISTS cache (path TEXT PRIMARY_KEY, sha256 TEXT, is_infected BOOLEAN, score REAL, status TEXT, timestamp REAL)")
            conn.commit()
            return conn
        except sqlite3.Error as e:
            logging.error(f"Ошибка инициализации кэша: {e}")
            return None

    def load_signatures(self):
        try:
            if not os.path.exists(self.signature_db):
                default = {
                    "sha256": ["d41d8cd98f00b204e9800998ecf8427e"],
                    "patterns": ["eval(", "exec(", "powershell", "cmd.exe", "trojan", "ransom"]
                }
                with open(self.signature_db, "w") as f:
                    json.dump(default, f)
                return default
            with open(self.signature_db, "r") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Ошибка загрузки сигнатур: {e}")
            return {"sha256": [], "patterns": []}

    def load_history(self):
        try:
            if not os.path.exists(self.history_file):
                return []
            with open(self.history_file, "r") as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            logging.error(f"Ошибка загрузки истории: {e}")
            return []

    def save_history(self, entry):
        try:
            self.scan_history.append(entry)
            with open(self.history_file, "w") as f:
                json.dump(self.scan_history[-100:], f)
        except (IOError, json.JSONEncodeError) as e:
            logging.error(f"Ошибка сохранения истории: {e}")

    def load_blocklist(self):
        try:
            if not os.path.exists("phishing_blocklist.txt"):
                with open("phishing_blocklist.txt", "w") as f:
                    f.write("example-phishing.com\nmalicious-site.net")
            with open("phishing_blocklist.txt", "r") as f:
                return set(line.strip() for line in f if line.strip())
        except Exception as e:
            logging.error(f"Ошибка загрузки блоклиста: {e}")
            return set()

    async def update_signatures_async(self):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(MALWAREBAZAAR_API, data={"query": "get_recent", "limit": 200}) as response:
                    samples = (await response.json()).get("data", [])
                    new_hashes = [sample["sha256_hash"] for sample in samples]
                    self.signatures["sha256"].extend(h for h in new_hashes if h not in self.signatures["sha256"])
                    with open(self.signature_db, "w") as f:
                        json.dump(self.signatures, f)
                    notification.notify(title="FOREVER AI", message=f"Добавлено {len(new_hashes)} сигнатур")
        except Exception as e:
            logging.error(f"Ошибка обновления сигнатур: {e}")

    async def check_phishing_url(self, url):
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            if domain in self.blocklist:
                return True, "Фишинговый сайт (блоклист)"
            return False, "Безопасно"
        except Exception as e:
            logging.error(f"Ошибка проверки URL {url}: {e}")
            return False, str(e)

    def monitor_network_connections(self):
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr and self.network_monitor_active:
                    ip = conn.raddr.ip
                    port = conn.raddr.port
                    if ip in self.malicious_ips:
                        return True, f"Подозрительное соединение с {ip}"
                    if port in [4444, 6666, 6667]:
                        return True, f"Подозрительный порт {port}"
            return False, "Сеть чиста"
        except Exception as e:
            logging.error(f"Ошибка мониторинга сети: {e}")
            return False, "Ошибка мониторинга"

    def check_unauthorized_access(self):
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr and conn.status == 'LISTEN' and conn.laddr.port not in [80, 443, 22]:
                    return True, f"Неавторизованный порт {conn.laddr.port}"
            return False, "Нет угроз"
        except Exception as e:
            logging.error(f"Ошибка проверки доступа: {e}")
            return False, "Ошибка проверки"

    def scan_browser_extensions(self):
        threats = []
        try:
            if SYSTEM == "Windows":
                chrome_path = os.path.expanduser("~/AppData/Local/Google/Chrome/User Data/Default/Extensions")
            else:
                chrome_path = os.path.expanduser("~/.config/google-chrome/Default/Extensions")
            if os.path.exists(chrome_path):
                for ext_dir in glob.glob(os.path.join(chrome_path, "*")):
                    manifest = os.path.join(ext_dir, "manifest.json")
                    if os.path.exists(manifest):
                        with open(manifest, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            if "permissions" in data and any(p in ["activeTab", "scripting", "webRequest"] for p in data["permissions"]):
                                _, sha256 = self.calculate_hashes(manifest)
                                if sha256 in self.signatures["sha256"]:
                                    threats.append(f"Подозрительное расширение Chrome: {os.path.basename(ext_dir)}")
            if SYSTEM == "Windows":
                firefox_path = os.path.expanduser("~/AppData/Roaming/Mozilla/Firefox/Profiles/*/extensions")
            else:
                firefox_path = os.path.expanduser("~/.mozilla/firefox/*/extensions")
            for ext_file in glob.glob(firefox_path):
                _, sha256 = self.calculate_hashes(ext_file)
                if sha256 in self.signatures["sha256"]:
                    threats.append(f"Подозрительное расширение Firefox: {os.path.basename(ext_file)}")
        except Exception as e:
            logging.error(f"Ошибка сканирования расширений браузера: {e}")
        return threats

    def scan_system_processes(self):
        threats = []
        try:
            for proc in psutil.process_iter(['name', 'exe', 'cpu_percent']):
                try:
                    if proc.info['exe']:
                        _, sha256 = self.calculate_hashes(proc.info['exe'])
                        if sha256 in self.signatures["sha256"]:
                            threats.append(f"Подозрительный процесс: {proc.info['name']}")
                        elif proc.info['cpu_percent'] > 80 and "svchost" not in proc.info['name'].lower():
                            threats.append(f"Высокое потребление CPU: {proc.info['name']}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logging.error(f"Ошибка сканирования процессов: {e}")
        return threats

    def scan_downloaded_file(self, file_path):
        return self.scan_file(file_path, scan_depth="Быстрое")

    def control_program_execution(self, process_path):
        try:
            blake2, sha256 = self.calculate_hashes(process_path)
            if sha256 in self.signatures["sha256"]:
                return False, "Вредоносная программа"
            return True, "Запуск разрешён"
        except Exception as e:
            logging.error(f"Ошибка контроля программы {process_path}: {e}")
            return True, "Ошибка проверки"

    def compile_yara_rules(self):
        try:
            yara_file_path = os.path.abspath(self.yara_rules)
            if not os.path.exists(yara_file_path):
                logging.info(f"Файл YARA правил не найден, создаётся: {yara_file_path}")
                rules = """
                rule SuspiciousCode {
                    strings:
                        $a = "eval("
                        $b = "exec("
                    condition:
                        any of them
                }
                """
                os.makedirs(os.path.dirname(yara_file_path), exist_ok=True)
                with open(yara_file_path, "w", encoding='utf-8') as f:
                    f.write(rules)
                logging.info(f"Файл YARA правил успешно создан: {yara_file_path}")
            logging.info(f"Компиляция YARA правил из файла: {yara_file_path}")
            return yara.compile(filepath=yara_file_path)
        except Exception as e:
            logging.error(f"Ошибка компиляции YARA правил ({yara_file_path}): {e}")
            return None

    def load_ml_model(self):
        if tf is None:
            logging.warning("ML модель не загружена: TensorFlow недоступен")
            return None
        try:
            model = tf.keras.Sequential([
                tf.keras.layers.Dense(128, activation='relu', input_shape=(256,)),
                tf.keras.layers.Dense(64, activation='relu'),
                tf.keras.layers.Dense(1, activation='sigmoid')
            ])
            return model
        except Exception as e:
            logging.error(f"Ошибка загрузки ML модели: {e}")
            return None

    def calculate_hashes(self, file_path):
        try:
            if not os.path.isfile(file_path) or not os.access(file_path, os.R_OK) or os.path.splitext(file_path)[1].lower() in TEMP_EXTENSIONS:
                raise PermissionError("Нет доступа к файлу или временный файл")
            blake2 = hashlib.blake2b()
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                while chunk := f.read(CHUNK_SIZE):
                    blake2.update(chunk)
                    sha256.update(chunk)
            return blake2.hexdigest(), sha256.hexdigest()
        except Exception as e:
            logging.error(f"Ошибка вычисления хэшей для {file_path}: {e}")
            return None, None

    def pe_analysis(self, file_path):
        try:
            pe = pefile.PE(file_path)
            lief_pe = lief.parse(file_path)
            entropy = lief_pe.entropy if lief_pe else 0
            return entropy > 7.0, f"Энтропия: {entropy}", 0.8 if entropy > 7.0 else 0.2
        except Exception as e:
            logging.debug(f"PE анализ не удался: {e}")
            return False, "Не PE файл", 0.0

    def yara_scan(self, file_path):
        try:
            if self.yara_compiled:
                matches = self.yara_compiled.match(file_path)
                return bool(matches), f"YARA: {len(matches)} совпадений", 0.9 if matches else 0.0
            return False, "YARA не доступен", 0.0
        except Exception as e:
            logging.debug(f"YARA сканирование не удалось: {e}")
            return False, "Ошибка YARA", 0.0

    def ml_scan(self, file_path):
        if not self.ml_available:
            return False, "ML не доступен (TensorFlow отсутствует)", 0.0
        try:
            if self.ml_model:
                with open(file_path, "rb") as f:
                    data = np.frombuffer(f.read(1024), dtype=np.uint8)
                if len(data) < 256:
                    data = np.pad(data, (0, 256 - len(data)))
                else:
                    data = data[:256]
                prediction = self.ml_model.predict(np.array([data]), verbose=0)[0][0]
                return prediction > 0.7, f"ML: {prediction:.2f}", prediction
            return False, "ML не доступен", 0.0
        except Exception as e:
            logging.debug(f"ML сканирование не удалось: {e}")
            return False, "Ошибка ML", 0.0

    def scan_file(self, file_path, scan_depth="Глубокое"):
        if not os.path.isfile(file_path) or not os.access(file_path, os.R_OK) or os.path.splitext(file_path)[1].lower() in TEMP_EXTENSIONS:
            return False, "Файл недоступен", 0.0

        blake2, sha256 = self.calculate_hashes(file_path)
        if not sha256:
            return False, "Ошибка хэширования", 0.0
        if sha256 in self.signatures["sha256"]:
            self.save_history({"файл": file_path, "статус": "Вирус", "детали": "Совпадение MalwareBazaar", "оценка": 0.95, "время": time.ctime()})
            return True, "Совпадение MalwareBazaar", 0.95

        scores = []
        details = []

        if scan_depth == "Глубокое":
            pe_infected, pe_details, pe_score = self.pe_analysis(file_path)
            yara_infected, yara_details, yara_score = self.yara_scan(file_path)
            ml_infected, ml_details, ml_score = self.ml_scan(file_path)
            scores.extend([pe_score, yara_score, ml_score])
            details.extend([pe_details, yara_details, ml_details])
            is_infected = pe_infected or yara_infected or ml_infected
        else:
            is_infected, heuristic_details, heuristic_score = self.heuristic_scan(file_path)
            scores.append(heuristic_score)
            details.append(heuristic_details)

        final_score = np.mean(scores) if scores else 0.0
        status = "Вирус" if is_infected else "Чисто"
        self.update_cache(file_path, sha256, is_infected, final_score, "; ".join(details))
        self.save_history({"файл": file_path, "статус": status, "детали": "; ".join(details), "оценка": final_score, "время": time.ctime()})
        return is_infected, "; ".join(details), final_score

    def heuristic_scan(self, file_path):
        try:
            with open(file_path, "rb") as f:
                data = f.read(1024 * 1024)
            text = data.decode('utf-8', errors='ignore').lower()
            pattern_count = sum(text.count(p) for p in self.signatures["patterns"])
            score = min(pattern_count * 0.15, 1.0)
            return score > 0.5, f"Паттерны: {pattern_count}", score
        except Exception as e:
            logging.debug(f"Эвристика не удалась: {e}")
            return False, "Ошибка эвристики", 0.0

    def update_cache(self, file_path, sha256, is_infected, score, status):
        if self.db_conn:
            try:
                self.db_conn.execute(
                    "INSERT OR REPLACE INTO cache (path, sha256, is_infected, score, status, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                    (file_path, sha256, is_infected, score, status, time.time())
                )
                self.db_conn.commit()
            except sqlite3.Error as e:
                logging.error(f"Ошибка обновления кэша: {e}")

    def quarantine_file(self, file_path):
        try:
            quarantine_path = os.path.join(self.quarantine_folder, f"q_{os.path.basename(file_path)}_{int(time.time())}")
            shutil.move(file_path, quarantine_path)
            notification.notify(title="FOREVER AI", message=f"Файл {os.path.basename(file_path)} в карантине")
            return True, quarantine_path
        except Exception as e:
            logging.error(f"Ошибка карантина: {e}")
            return False, str(e)

    def get_threat_level(self, score):
        if score >= 0.9:
            return "Критический"
        elif score >= 0.6:
            return "Высокий"
        elif score >= 0.3:
            return "Средний"
        else:
            return "Низкий"

class ScanResultsWindow(QMainWindow):
    def __init__(self, antivirus):
        super().__init__()
        self.antivirus = antivirus
        self.setWindowTitle("Результаты сканирования")
        self.setGeometry(200, 200, 1200, 700)
        self.init_ui()

    def init_ui(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        layout = QVBoxLayout(self.central_widget)
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Путь", "Статус", "Детали", "Уровень угрозы", "Оценка", "Действие"])
        layout.addWidget(self.table)
        self.close_btn = QPushButton("Закрыть")
        self.close_btn.clicked.connect(self.close)
        layout.addWidget(self.close_btn)

    def add_result(self, result):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(result["путь"]))
        self.table.setItem(row, 1, QTableWidgetItem(result["статус"]))
        self.table.setItem(row, 2, QTableWidgetItem(result["детали"]))
        self.table.setItem(row, 3, QTableWidgetItem(result["уровень_угрозы"]))
        self.table.setItem(row, 4, QTableWidgetItem(f"{result['оценка']:.2f}"))
        if result["статус"] == "Вирус" and os.path.exists(result["путь"]):
            btn = QPushButton("В карантин")
            btn.clicked.connect(lambda: self.antivirus.quarantine_file(result["путь"]))
            self.table.setCellWidget(row, 5, btn)
        else:
            self.table.setItem(row, 5, QTableWidgetItem("Недоступно"))

class ForeverAIApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.antivirus = SuperAntivirus()
        self.init_ui()
        self.setStyleSheet(dark_stylesheet)
        self.setup_tray()
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_signatures)
        self.timer.start(15 * 60 * 1000)
        self.start_realtime_monitoring()
        self.start_network_monitoring()
        self.start_browser_monitoring()
        self.start_system_monitoring()

    def init_ui(self):
        self.setWindowTitle("FOREVER AI")
        self.setGeometry(100, 100, 1400, 900)
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)

        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(250)
        items = ["Сканирование", "Карантин", "Настройки", "Статистика", "О программе"]
        for item in items:
            self.sidebar.addItem(QListWidgetItem(item))
        self.sidebar.currentRowChanged.connect(self.switch_tab)
        main_layout.addWidget(self.sidebar)

        self.content = QStackedWidget()
        self.content.addWidget(self.create_scan_widget())
        self.content.addWidget(self.create_quarantine_widget())
        self.content.addWidget(self.create_settings_widget())
        self.content.addWidget(self.create_stats_widget())
        self.content.addWidget(self.create_about_widget())
        main_layout.addWidget(self.content)

    def create_scan_widget(self):
        widget = QWidget()
        layout = QVBoxLayout()

        dashboard = QWidget()
        dash_layout = QHBoxLayout()

        status_card = QWidget()
        status_layout = QVBoxLayout()
        self.status_label = QLabel("Компьютер защищён")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        status_layout.addWidget(self.status_label)
        if not self.antivirus.ml_available:
            ml_warning = QLabel("ML функции отключены: TensorFlow недоступен")
            ml_warning.setStyleSheet("color: red; font-size: 14px;")
            status_layout.addWidget(ml_warning)
        status_card.setLayout(status_layout)
        status_card.setStyleSheet("background-color: #252525; border-radius: 10px; padding: 15px;")
        dash_layout.addWidget(status_card)

        network_card = QWidget()
        network_layout = QVBoxLayout()
        self.network_label = QLabel("Сеть: Безопасно")
        self.network_label.setAlignment(Qt.AlignCenter)
        network_layout.addWidget(self.network_label)
        network_card.setLayout(network_layout)
        network_card.setStyleSheet("background-color: #252525; border-radius: 10px; padding: 15px;")
        dash_layout.addWidget(network_card)

        dashboard.setLayout(dash_layout)
        layout.addWidget(dashboard)

        scan_layout = QHBoxLayout()
        self.scan_btn = QPushButton("Сканировать папку")
        self.scan_btn.setToolTip("Выберите папку для проверки")
        self.scan_btn.clicked.connect(self.scan_dialog)
        scan_layout.addWidget(self.scan_btn)

        quick_scan_btn = QPushButton("Быстрое сканирование")
        quick_scan_btn.setToolTip("Проверка загрузок и рабочего стола")
        quick_scan_btn.clicked.connect(self.start_quick_scan)
        scan_layout.addWidget(quick_scan_btn)

        layout.addLayout(scan_layout)

        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        self.threat_list = QListWidget()
        self.threat_list.setMaximumHeight(200)
        layout.addWidget(QLabel("Последние угрозы:"))
        layout.addWidget(self.threat_list)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def create_quarantine_widget(self):
        widget = QWidget()
        layout = QVBoxLayout()
        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(6)
        self.quarantine_table.setHorizontalHeaderLabels(["Файл", "Статус", "Дата", "Восстановить", "Удалить", "Выбрать"])
        layout.addWidget(self.quarantine_table)
        btn_layout = QHBoxLayout()
        update_btn = QPushButton("Обновить")
        update_btn.clicked.connect(self.update_quarantine)
        btn_layout.addWidget(update_btn)
        bulk_restore_btn = QPushButton("Восстановить выбранные")
        bulk_restore_btn.clicked.connect(self.bulk_restore)
        btn_layout.addWidget(bulk_restore_btn)
        bulk_delete_btn = QPushButton("Удалить выбранные")
        bulk_delete_btn.clicked.connect(self.bulk_delete)
        btn_layout.addWidget(bulk_delete_btn)
        layout.addLayout(btn_layout)
        widget.setLayout(layout)
        return widget

    def create_settings_widget(self):
        widget = QWidget()
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Глубина сканирования:"))
        self.scan_depth_combo = QComboBox()
        self.scan_depth_combo.addItems(["Быстрое", "Глубокое"])
        layout.addWidget(self.scan_depth_combo)

        layout.addWidget(QLabel("Интенсивность сканирования:"))
        self.scan_intensity_combo = QComboBox()
        self.scan_intensity_combo.addItems(["Низкая", "Средняя", "Высокая"])
        self.scan_intensity_combo.currentTextChanged.connect(self.adjust_scan_intensity)
        layout.addWidget(self.scan_intensity_combo)

        layout.addWidget(QLabel("Мониторинг сети:"))
        self.network_monitor_toggle = QCheckBox("Включить мониторинг сетевых угроз")
        self.network_monitor_toggle.setChecked(True)
        self.network_monitor_toggle.stateChanged.connect(self.toggle_network_monitor)
        layout.addWidget(self.network_monitor_toggle)

        layout.addWidget(QLabel("Мониторинг браузеров:"))
        self.browser_monitor_toggle = QCheckBox("Включить мониторинг браузеров")
        self.browser_monitor_toggle.setChecked(True)
        self.browser_monitor_toggle.stateChanged.connect(self.toggle_browser_monitor)
        layout.addWidget(self.browser_monitor_toggle)

        layout.addWidget(QLabel("Мониторинг системы:"))
        self.system_monitor_toggle = QCheckBox("Включить мониторинг процессов")
        self.system_monitor_toggle.setChecked(True)
        self.system_monitor_toggle.stateChanged.connect(self.toggle_system_monitor)
        layout.addWidget(self.system_monitor_toggle)

        layout.addWidget(QLabel("Добавить URL в блоклист:"))
        blocklist_layout = QHBoxLayout()
        self.blocklist_input = QTextEdit()
        self.blocklist_input.setMaximumHeight(50)
        blocklist_layout.addWidget(self.blocklist_input)
        add_blocklist_btn = QPushButton("Добавить")
        add_blocklist_btn.clicked.connect(self.add_to_blocklist)
        blocklist_layout.addWidget(add_blocklist_btn)
        layout.addLayout(blocklist_layout)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def create_stats_widget(self):
        widget = QWidget()
        layout = QVBoxLayout()
        self.cpu_label = QLabel("CPU: 0%")
        self.memory_label = QLabel("Память: 0 MB")
        layout.addWidget(self.cpu_label)
        layout.addWidget(self.memory_label)
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats)
        self.stats_timer.start(5000)
        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def create_about_widget(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("FOREVER AI v2.0\nРазработчик: @fRoMiX73\nФункции: Сканирование, защита сети, мониторинг браузеров и системы"))
        widget.setLayout(layout)
        return widget

    def switch_tab(self, index):
        self.content.setCurrentIndex(index)

    def setup_tray(self):
        self.tray = QSystemTrayIcon(self)
        icon_path = os.path.abspath(ICON_PATH)
        if os.path.exists(icon_path):
            self.tray.setIcon(QIcon(icon_path))
            logging.info(f"Иконка загружена: {icon_path}")
        else:
            logging.warning(f"Иконка не найдена по пути: {icon_path}. Используется системная иконка.")
            self.tray.setIcon(QIcon.fromTheme("security-high", QIcon()))  # Запасная пустая иконка
        self.tray.setToolTip("FOREVER AI")
        menu = QMenu()
        menu.addAction("Показать", self.show)
        menu.addAction("Выход", QApplication.quit)
        self.tray.setContextMenu(menu)
        self.tray.show()

    def update_signatures(self):
        if psutil.cpu_percent() < 80:
            asyncio.run(self.antivirus.update_signatures_async())

    def scan_dialog(self):
        folder = QFileDialog.getExistingDirectory(self, "Выберите папку")
        if folder:
            self.status_label.setText(f"Сканирование: {folder}")
            worker = ScanWorker(self.antivirus, folder, self.scan_depth_combo.currentText())
            worker.result_signal.connect(self.show_results)
            worker.progress_signal.connect(self.progress_bar.setValue)
            worker.current_file_signal.connect(lambda path: self.status_label.setText(f"Сканирование: {os.path.basename(path)}"))
            worker.finished_signal.connect(self.scan_finished)
            worker.start()
            self.scan_btn.setEnabled(False)

    def start_quick_scan(self):
        critical_dirs = [os.path.expanduser("~/Downloads"), os.path.expanduser("~/Desktop")]
        for folder in critical_dirs:
            if os.path.exists(folder):
                self.status_label.setText(f"Быстрое сканирование: {folder}")
                worker = ScanWorker(self.antivirus, folder, "Быстрое")
                worker.result_signal.connect(self.show_results)
                worker.progress_signal.connect(self.progress_bar.setValue)
                worker.current_file_signal.connect(lambda path: self.status_label.setText(f"Сканирование: {os.path.basename(path)}"))
                worker.finished_signal.connect(self.scan_finished)
                worker.start()
                self.scan_btn.setEnabled(False)
                break

    def scan_finished(self):
        self.status_label.setText("Сканирование завершено")
        self.scan_btn.setEnabled(True)

    def show_results(self, result):
        if not hasattr(self, 'results_window') or not self.results_window.isVisible():
            self.results_window = ScanResultsWindow(self.antivirus)
            self.results_window.show()
        self.results_window.add_result(result)

    def update_quarantine(self):
        self.quarantine_table.setRowCount(0)
        try:
            for file in os.listdir(self.antivirus.quarantine_folder):
                row = self.quarantine_table.rowCount()
                self.quarantine_table.insertRow(row)
                self.quarantine_table.setItem(row, 0, QTableWidgetItem(file))
                self.quarantine_table.setItem(row, 1, QTableWidgetItem("В карантине"))
                mod_time = time.ctime(os.path.getmtime(os.path.join(self.antivirus.quarantine_folder, file)))
                self.quarantine_table.setItem(row, 2, QTableWidgetItem(mod_time))
                restore_btn = QPushButton("Восстановить")
                restore_btn.clicked.connect(lambda _, f=file: self.restore_file(f))
                self.quarantine_table.setCellWidget(row, 3, restore_btn)
                delete_btn = QPushButton("Удалить")
                delete_btn.clicked.connect(lambda _, f=file: self.delete_file(f))
                self.quarantine_table.setCellWidget(row, 4, delete_btn)
                checkbox = QCheckBox()
                self.quarantine_table.setCellWidget(row, 5, checkbox)
        except Exception as e:
            logging.error(f"Ошибка обновления карантина: {e}")
            self.status_label.setText(f"Ошибка карантина")

    def bulk_restore(self):
        for row in range(self.quarantine_table.rowCount()):
            checkbox = self.quarantine_table.cellWidget(row, 5)
            if checkbox.isChecked():
                filename = self.quarantine_table.item(row, 0).text()
                self.restore_file(filename)
        self.update_quarantine()

    def bulk_delete(self):
        for row in range(self.quarantine_table.rowCount()):
            checkbox = self.quarantine_table.cellWidget(row, 5)
            if checkbox.isChecked():
                filename = self.quarantine_table.item(row, 0).text()
                self.delete_file(filename)
        self.update_quarantine()

    def restore_file(self, filename):
        try:
            src = os.path.join(self.antivirus.quarantine_folder, filename)
            dest = os.path.expanduser(f"~/Restored_{filename}")
            shutil.move(src, dest)
            notification.notify(title="FOREVER AI", message=f"Файл восстановлен")
            self.update_quarantine()
        except Exception as e:
            logging.error(f"Ошибка восстановления {filename}: {e}")

    def delete_file(self, filename):
        try:
            os.remove(os.path.join(self.antivirus.quarantine_folder, filename))
            notification.notify(title="FOREVER AI", message=f"Файл удалён")
            self.update_quarantine()
        except Exception as e:
            logging.error(f"Ошибка удаления {filename}: {e}")

    def start_realtime_monitoring(self):
        try:
            if not hasattr(self, 'observer') or not self.observer.is_alive():
                self.observer = Observer()
                self.observer.schedule(RealTimeMonitor(self.antivirus), path=os.path.expanduser("~"), recursive=True)
                self.observer.start()
                logging.info("Мониторинг в реальном времени запущен")
        except Exception as e:
            logging.error(f"Ошибка запуска мониторинга: {e}")

    def start_network_monitoring(self):
        try:
            if not hasattr(self, 'network_monitor') or not self.network_monitor.isRunning():
                self.network_monitor = NetworkMonitor(self.antivirus)
                self.network_monitor.threat_signal.connect(self.show_network_threat)
                self.network_monitor.start()
                logging.info("Мониторинг сети запущен")
        except Exception as e:
            logging.error(f"Ошибка запуска мониторинга сети: {e}")

    def start_browser_monitoring(self):
        try:
            if not hasattr(self, 'browser_monitor') or not self.browser_monitor.isRunning():
                self.browser_monitor = BrowserMonitor(self.antivirus)
                self.browser_monitor.threat_signal.connect(self.show_network_threat)
                self.browser_monitor.start()
                logging.info("Мониторинг браузеров запущен")
        except Exception as e:
            logging.error(f"Ошибка запуска мониторинга браузеров: {e}")

    def start_system_monitoring(self):
        try:
            if not hasattr(self, 'system_monitor') or not self.system_monitor.isActive():
                self.system_monitor = QTimer()
                self.system_monitor.timeout.connect(self.scan_system)
                self.system_monitor.start(30000)
                logging.info("Мониторинг системы запущен")
        except Exception as e:
            logging.error(f"Ошибка запуска мониторинга системы: {e}")

    def scan_system(self):
        if self.antivirus.system_monitor_active:
            threats = self.antivirus.scan_system_processes()
            for threat in threats:
                self.show_network_threat({"тип": "Система", "детали": threat})

    def show_network_threat(self, threat):
        self.status_label.setText(f"Угроза: {threat['детали']}")
        self.network_label.setText(f"{threat['тип']}: Угроза")
        item = QListWidgetItem(f"{threat['тип']}: {threat['детали']}")
        self.threat_list.addItem(item)
        notification.notify(
            title=f"FOREVER AI: {threat['тип']}",
            message=threat["детали"]
        )

    def toggle_network_monitor(self, state):
        self.antivirus.network_monitor_active = bool(state)
        self.network_label.setText("Сеть: " + ("Активно" if state else "Отключено"))
        if state and (not hasattr(self, 'network_monitor') or not self.network_monitor.isRunning()):
            self.start_network_monitoring()

    def toggle_browser_monitor(self, state):
        if state:
            self.start_browser_monitoring()
        else:
            if hasattr(self, 'browser_monitor') and self.browser_monitor.isRunning():
                self.browser_monitor.stop()
                self.browser_monitor.wait(5000)

    def toggle_system_monitor(self, state):
        self.antivirus.system_monitor_active = bool(state)
        if state:
            self.start_system_monitoring()
        else:
            if hasattr(self, 'system_monitor') and self.system_monitor.isActive():
                self.system_monitor.stop()

    def adjust_scan_intensity(self, intensity):
        global MAX_CONCURRENT_SCANS
        if intensity == "Низкая":
            MAX_CONCURRENT_SCANS = 2
        elif intensity == "Средняя":
            MAX_CONCURRENT_SCANS = 4
        else:
            MAX_CONCURRENT_SCANS = 8
        self.antivirus.executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_SCANS)

    def add_to_blocklist(self):
        url = self.blocklist_input.toPlainText().strip()
        if url:
            self.antivirus.blocklist.add(url)
            with open("phishing_blocklist.txt", "a") as f:
                f.write(f"{url}\n")
            self.blocklist_input.clear()
            notification.notify(title="FOREVER AI", message=f"URL добавлен")

    def update_stats(self):
        cpu = psutil.cpu_percent()
        memory = psutil.virtual_memory().used / 1024 / 1024
        self.cpu_label.setText(f"CPU: {cpu:.1f}%")
        self.memory_label.setText(f"Память: {memory:.1f} MB")

    def closeEvent(self, event):
        logging.info("Закрытие приложения")
        if hasattr(self, 'antivirus') and self.antivirus.db_conn:
            try:
                self.antivirus.db_conn.close()
                logging.info("База данных закрыта")
            except Exception as e:
                logging.error(f"Ошибка закрытия базы данных: {e}")
        if hasattr(self, 'timer') and self.timer.isActive():
            self.timer.stop()
            logging.info("Таймер обновления сигнатур остановлен")
        if hasattr(self, 'network_monitor') and self.network_monitor.isRunning():
            self.network_monitor.stop()
            self.network_monitor.wait(5000)
            logging.info("Мониторинг сети остановлен")
        if hasattr(self, 'browser_monitor') and self.browser_monitor.isRunning():
            self.browser_monitor.stop()
            self.browser_monitor.wait(5000)
            logging.info("Мониторинг браузеров остановлен")
        if hasattr(self, 'observer') and self.observer.is_alive():
            self.observer.stop()
            try:
                self.observer.join(timeout=5.0)
                logging.info("Мониторинг файловой системы остановлен")
            except TimeoutError:
                logging.warning("Мониторинг файловой системы не завершился вовремя")
        if hasattr(self, 'stats_timer') and self.stats_timer.isActive():
            self.stats_timer.stop()
            logging.info("Таймер статистики остановлен")
        if hasattr(self, 'system_monitor') and self.system_monitor.isActive():
            self.system_monitor.stop()
            logging.info("Мониторинг системы остановлен")
        event.accept()

dark_stylesheet = """
QWidget {
    background-color: #1e1e1e;
    color: #e0e0e0;
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 14px;
}
QPushButton {
    background-color: #0288d1;
    border-radius: 8px;
    padding: 10px;
    color: white;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #039be5;
}
QPushButton:pressed {
    background-color: #0277bd;
}
QTableWidget {
    background-color: #252525;
    gridline-color: #333333;
}
QTableWidget::item {
    padding: 5px;
}
QProgressBar {
    border: 1px solid #333333;
    border-radius: 5px;
    text-align: center;
}
QProgressBar::chunk {
    background-color: #0288d1;
}
QListWidget {
    background-color: #252525;
    border: none;
}
QListWidget::item {
    padding: 10px;
    border-bottom: 1px solid #333333;
}
QListWidget::item:selected {
    background-color: #0288d1;
    color: white;
}
QComboBox {
    background-color: #252525;
    border: 1px solid #333333;
    padding: 5px;
    border-radius: 4px;
}
QTextEdit {
    background-color: #252525;
    border: 1px solid #333333;
    padding: 5px;
    border-radius: 4px;
}
QCheckBox {
    color: #e0e0e0;
}
"""

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ForeverAIApp()
    window.show()
    sys.exit(app.exec_())