import logging
import platform

# Определяем фильтр для добавления информации о системе
class SystemFilter(logging.Filter):
    def __init__(self):
        super().__init__()
        self.system = platform.system()

    def filter(self, record):
        record.system = self.system
        return True

# Функция настройки логирования
def setup_logging(log_file='app.log', level=logging.DEBUG):
    """
    Настраивает логирование с указанным файлом и уровнем.

    :param log_file: Путь к файлу лога (по умолчанию 'app.log')
    :param level: Уровень логирования (по умолчанию DEBUG)
    """
    try:
        # Создаем логгер
        logger = logging.getLogger()
        logger.setLevel(level)

        # Создаем обработчик для записи в файл
        handler = logging.FileHandler(log_file)
        handler.setLevel(level)

        # Задаем формат сообщений
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - [System: %(system)s] - %(message)s')
        handler.setFormatter(formatter)

        # Добавляем фильтр для информации о системе
        handler.addFilter(SystemFilter())

        # Добавляем обработчик к логгеру
        logger.addHandler(handler)

        # Логируем успешную настройку
        logger.info('Логирование успешно настроено')
    except PermissionError as e:
        print(f'Ошибка: Нет прав для записи в файл {log_file}: {e}')
    except Exception as e:
        print(f'Ошибка при настройке логирования: {e}')

# Пример использования
if __name__ == '__main__':
    # Настраиваем логирование
    setup_logging(log_file='better_than_avast.log')

    # Тестовые сообщения
    logging.debug('Это сообщение уровня DEBUG')
    logging.info('Это сообщение уровня INFO')
    logging.warning('Это сообщение уровня WARNING')
    logging.error('Это сообщение уровня ERROR')