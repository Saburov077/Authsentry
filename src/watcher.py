import time
from typing import Generator

def follow_log(filepath: str, poll_interval: float = 0.5) -> Generator[str, None, None]:
    """
    Генератор по аналогии с `tail -f`: открывает файл, переходит в конец
    и непрерывно возвращает новые строки по мере их записи.
    """
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        # Перемещаем указатель в конец файла, чтобы не перечитывать старые события
        f.seek(0, 2)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            yield line