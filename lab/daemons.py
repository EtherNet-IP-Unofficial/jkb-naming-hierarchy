"""Launch, monitor and reap the per-namespace service processes."""

import os
import threading
from pathlib import Path
from subprocess import Popen, STDOUT

from models import Daemon


class DaemonManager():

    def __init__(self, shell, output_dir:Path):
        self.shell = shell
        self.output_dir = Path(output_dir)
        self.daemons = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def spawn(self, ns_id:str, cmd:list, env_dict:dict|None=None) -> None:
        # Daemons stay in foreground under our control so we can kill them later.
        full = ["ip", "netns", "exec", ns_id, *cmd]
        env_final = os.environ.copy()
        if env_dict is not None:
            env_final.update(env_dict)
            full = [self.shell.sudo_provider, "-E", *full]
        else:
            full = [self.shell.sudo_provider, *full]

        # Merge stdout+stderr into one per-daemon log so we can replay it on death.
        label = f"{ns_id}-{Path(cmd[0]).name}"
        log_path = self.output_dir / f"{label}.log"
        log_fp = open(log_path, "w+")
        proc = Popen(full, stdout=log_fp, stderr=STDOUT, env=env_final)
        with self._lock:
            self.daemons.append(Daemon(label=label, proc=proc, log_path=log_path, log_fp=log_fp))
        print(f"Daemon started: {' '.join(full)} (log: {log_path})")

    def start_monitor(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._monitor, daemon=True)
        self._thread.start()

    def _monitor(self) -> None:
        # Poll every second; report and drop any daemon that has exited.
        while not self._stop.is_set():
            with self._lock:
                alive = []
                for a_daemon in self.daemons:
                    if a_daemon.proc.poll() is None:
                        alive.append(a_daemon)
                    else:
                        self._report_dead(a_daemon)
                self.daemons = alive
            self._stop.wait(1.0)

    def _report_dead(self, daemon:Daemon) -> None:
        try:
            daemon.log_fp.flush()
            daemon.log_fp.seek(0)
            output = daemon.log_fp.read()
        except (OSError, ValueError):
            output = ""
        finally:
            try:
                daemon.log_fp.close()
            except OSError:
                pass
        print(f"\n=== Daemon '{daemon.label}' exited (rc={daemon.proc.returncode}) ===")
        print(output, end="" if output.endswith("\n") else "\n")
        print(f"=== end '{daemon.label}' ===\n")

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        with self._lock:
            for a_daemon in self.daemons:
                a_daemon.proc.terminate()
                try:
                    a_daemon.log_fp.close()
                except OSError:
                    pass
            self.daemons = []
