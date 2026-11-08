"""OS-held per-database lease; process death releases it, files are not PID proof."""
import os
from pathlib import Path


class SessionBusy(RuntimeError):
    pass


class SessionLock:
    def __init__(self, db):
        self.path = Path(str(Path(db).resolve()) + '.bridge.lock')
        self.handle = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        self.handle = self.path.open('a+b')
        try:
            if os.name == 'nt':
                import msvcrt
                self.handle.seek(0)
                if self.handle.read(1) == b'':
                    self.handle.write(b'0'); self.handle.flush()
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.handle.close(); self.handle = None
            raise SessionBusy('Live bridge or recovery owns this database') from None
        return self

    def __exit__(self, *args):
        if self.handle:
            self.handle.close(); self.handle = None
