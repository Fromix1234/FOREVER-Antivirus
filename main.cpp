#include <QApplication>
#include <QWidget>
#include <QVBoxLayout>
#include <QPushButton>
#include <QTextEdit>
#include <QProgressBar>
#include <QLabel>
#include <QThread>
#include <QTimer>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QCryptographicHash>
#include <QFile>
#include <QDir>
#include <QDebug>

class ScanWorker : public QThread {
    Q_OBJECT
public:
    ScanWorker(const QString& target, QObject* parent = nullptr) : QThread(parent), target(target), running(true) {}
    void stop() { running = false; wait(); }

signals:
    void result(const QString& result);
    void progress(int value);

protected:
    void run() override {
        QDir dir(target);
        QFileInfoList files = dir.entryInfoList(QDir::Files | QDir::NoDotAndDotDot, QDir::Name);
        int total = files.size();
        for (int i = 0; i < total && running; ++i) {
            QString filePath = files[i].absoluteFilePath();
            bool isInfected = scanFile(filePath);
            QString result = isInfected ? QString("Threat: %1").arg(filePath) : QString("Clean: %1").arg(filePath);
            emit result(result);
            emit progress((i + 1) * 100 / total);
        }
    }

private:
    QString target;
    volatile bool running;

    bool scanFile(const QString& filePath) {
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly)) return false;

        QByteArray data = file.read(1024 * 1024); // Читаем до 1 МБ
        QString text = QString(data).toLower();

        // Проверка сигнатур
        QSqlQuery query;
        query.exec("SELECT sha256 FROM signatures");
        while (query.next()) {
            QString sig = query.value(0).toString();
            QByteArray hash = QCryptographicHash::hash(QFile(filePath).readAll(), QCryptographicHash::Sha256).toHex();
            if (hash == sig.toUtf8()) return true;
        }

        // Эвристика
        QStringList patterns = {"eval(", "exec(", "powershell", "cmd.exe", "http", "socket", "malware",
                               "rundll32", "regsvr32", "mshta", "vbscript", "javascript", "wget", "curl",
                               "trojan", "backdoor", "exploit", "ransom", "dropper", "keylogger",
                               "virus", "worm", "spyware", "adware"};
        int patternCount = 0;
        for (const QString& p : patterns) {
            if (text.contains(p)) patternCount++;
        }
        qint64 size = QFileInfo(filePath).size();
        bool suspiciousExt = filePath.endsWith(".exe") || filePath.endsWith(".bat") || filePath.endsWith(".dll");
        float score = patternCount * 0.25 + (size > 500000) * 0.2 + suspiciousExt * 0.3;
        return score > 0.6;
    }
};

class AntivirusApp : public QWidget {
    Q_OBJECT
public:
    AntivirusApp(QWidget* parent = nullptr) : QWidget(parent), threatCount(0) {
        setupDatabase();
        setupUI();
        setupTray();

        updateTimer = new QTimer(this);
        connect(updateTimer, &QTimer::timeout, this, &AntivirusApp::flushResults);
        updateTimer->start(100);
    }

    ~AntivirusApp() {
        for (auto worker : activeWorkers) {
            worker->stop();
            delete worker;
        }
        QSqlDatabase::database().close();
    }

private slots:
    void scanSystem() {
        scanTarget(QDir::homePath());
    }

    void cleanThreats() {
        results->clear();
        threatCount = 0;
        cleanBtn->setEnabled(false);
        updateStatus();
    }

    void bufferResult(const QString& result) {
        resultBuffer.append(result);
        if (result.startsWith("Threat")) {
            threatCount++;
            QString filePath = result.split(": ")[1];
            quarantineFile(filePath);
        }
    }

    void updateProgress(int value) {
        progressBar->setValue(value);
    }

    void onScanFinished() {
        if (threatCount > 0) cleanBtn->setEnabled(true);
        ScanWorker* worker = qobject_cast<ScanWorker*>(sender());
        activeWorkers.removeAll(worker);
        delete worker;
    }

    void flushResults() {
        if (!resultBuffer.isEmpty()) {
            for (const QString& result : resultBuffer) {
                QString color = result.startsWith("Threat") ? "#d32f2f" : "#0078d4";
                results->append(QString("<span style='color: %1'>%2</span>").arg(color, result));
            }
            resultBuffer.clear();
            updateStatus();
        }
    }

    void quitApp() {
        for (auto worker : activeWorkers) worker->stop();
        updateTimer->stop();
        QApplication::quit();
    }

private:
    QLabel* statusLabel;
    QPushButton* scanBtn;
    QPushButton* cleanBtn;
    QProgressBar* progressBar;
    QTextEdit* results;
    QSystemTrayIcon* tray;
    QTimer* updateTimer;
    QList<ScanWorker*> activeWorkers;
    QStringList resultBuffer;
    int threatCount;

    void setupDatabase() {
        QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
        db.setDatabaseName("antivirus_cache.db");
        if (!db.open()) {
            qDebug() << "Failed to open database";
            return;
        }

        QSqlQuery query;
        query.exec("CREATE TABLE IF NOT EXISTS signatures (sha256 TEXT PRIMARY KEY, description TEXT)");
        query.exec("INSERT OR IGNORE INTO signatures VALUES ('d41d8cd98f00b204e9800998ecf8427e', 'Empty file')");
        query.exec("INSERT OR IGNORE INTO signatures VALUES ('68e109f0f40ca72a15e05cc22786f8e6', 'EICAR test')");
        query.exec("INSERT OR IGNORE INTO signatures VALUES ('a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6', 'Trojan example')");
        query.exec("INSERT OR IGNORE INTO signatures VALUES ('b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7', 'Virus example')");
        query.exec("INSERT OR IGNORE INTO signatures VALUES ('e99a18c428cb38d5f260853678922e03', 'Malware example')");
    }

    void setupUI() {
        setWindowTitle("EasyProtect");
        setGeometry(100, 100, 800, 600);
        setStyleSheet(
            "QWidget { background: #ffffff; color: #333333; font-family: 'Arial'; font-size: 14px; }"
            "QPushButton { background: #0078d4; border: none; padding: 15px; border-radius: 8px; color: white; font-size: 16px; font-weight: bold; }"
            "QPushButton:hover { background: #005bb5; }"
            "QPushButton#clean { background: #d32f2f; }"
            "QPushButton#clean:hover { background: #b71c1c; }"
            "QTextEdit { background: #f5f5f5; border: 1px solid #e0e0e0; border-radius: 5px; padding: 10px; color: #333333; }"
            "QProgressBar { border: 1px solid #e0e0e0; border-radius: 5px; background: #f5f5f5; text-align: center; color: #333333; }"
            "QProgressBar::chunk { background: #0078d4; border-radius: 3px; }"
            "QLabel#status { font-size: 24px; font-weight: bold; padding: 10px; }"
            "QLabel#status_safe { color: #0078d4; }"
            "QLabel#status_threat { color: #d32f2f; }"
        );

        QVBoxLayout* layout = new QVBoxLayout(this);

        statusLabel = new QLabel("Ваш компьютер защищён", this);
        statusLabel->setObjectName("status");
        statusLabel->setAlignment(Qt::AlignCenter);
        layout->addWidget(statusLabel);

        QHBoxLayout* buttonLayout = new QHBoxLayout;
        scanBtn = new QPushButton("Сканировать", this);
        connect(scanBtn, &QPushButton::clicked, this, &AntivirusApp::scanSystem);
        buttonLayout->addWidget(scanBtn);

        cleanBtn = new QPushButton("Удалить угрозы", this);
        cleanBtn->setObjectName("clean");
        connect(cleanBtn, &QPushButton::clicked, this, &AntivirusApp::cleanThreats);
        cleanBtn->setEnabled(false);
        buttonLayout->addWidget(cleanBtn);
        layout->addLayout(buttonLayout);

        progressBar = new QProgressBar(this);
        layout->addWidget(progressBar);

        results = new QTextEdit(this);
        results->setReadOnly(true);
        layout->addWidget(results);
    }

    void setupTray() {
        QPixmap pixmap(16, 16);
        pixmap.fill(Qt::blue);
        tray = new QSystemTrayIcon(QIcon(pixmap), this);
        QMenu* menu = new QMenu(this);
        menu->addAction("Открыть", this, &QWidget::show);
        menu->addAction("Выход", this, &AntivirusApp::quitApp);
        tray->setContextMenu(menu);
        tray->show();
    }

    void scanTarget(const QString& target) {
        progressBar->setValue(0);
        threatCount = 0;
        cleanBtn->setEnabled(false);
        ScanWorker* worker = new ScanWorker(target);
        connect(worker, &ScanWorker::result, this, &AntivirusApp::bufferResult);
        connect(worker, &ScanWorker::progress, this, &AntivirusApp::updateProgress);
        connect(worker, &ScanWorker::finished, this, &AntivirusApp::onScanFinished);
        activeWorkers.append(worker);
        worker->start();
    }

    void quarantineFile(const QString& filePath) {
        QDir quarantineDir(QDir::homePath() + "/quarantine");
        if (!quarantineDir.exists()) quarantineDir.mkpath(".");
        QString newPath = quarantineDir.filePath(QString("q_%1_%2").arg(QFileInfo(filePath).fileName()).arg(QDateTime::currentMSecsSinceEpoch()));
        QFile::rename(filePath, newPath);
    }

    void updateStatus() {
        if (threatCount > 0) {
            statusLabel->setText(QString("Найдено угроз: %1").arg(threatCount));
            statusLabel->setObjectName("status_threat");
        } else {
            statusLabel->setText("Ваш компьютер защищён");
            statusLabel->setObjectName("status_safe");
        }
        statusLabel->setStyleSheet("");
    }
};

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    AntivirusApp window;
    window.show();
    return app.exec();
}

#include "main.moc"