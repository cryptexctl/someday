import argparse
import ast
import json
import logging
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Dict, Any, Optional, List, Tuple


@dataclass
class PluginMetadata:
    id: str
    name: str
    description: str
    author: str
    min_version: str


class AdbManager:
    def __init__(self):
        self.logger: logging.Logger = logging.getLogger("AdbManager")

    def run_command(self, command: List[str]) -> Optional[str]:
        try:
            result = subprocess.run(
                ["adb"] + command, check=True, capture_output=True, text=True
            )
            self.logger.debug(f"ADB command successful: {' '.join(command)}")
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            self.logger.error(f"ADB command failed: {e}")
            self.logger.error(f"Error output: {e.stderr}")
            return None

    def start_server(self):
        self.logger.info("Starting ADB server...")
        self.run_command(["start-server"])

    def wait_for_device(self):
        self.logger.info("Waiting for device to connect...")
        self.run_command(["wait-for-device"])
        self.logger.info("Device connected")

    def forward_port(self, local_port: int, remote_port: int) -> bool:
        self.logger.info(f"Forwarding port {local_port} to {remote_port}...")
        result = self.run_command(
            ["forward", f"tcp:{local_port}", f"tcp:{remote_port}"]
        )
        return result is not None

    def reverse_port(self, local_port: int, remote_port: int) -> bool:
        self.logger.info(f"Reverse forwarding port {remote_port}...")
        result = self.run_command(
            ["reverse", f"tcp:{local_port}", f"tcp:{remote_port}"]
        )
        return result is not None

    def setup_device(self, debug_mode: bool = False) -> bool:
        self.start_server()
        self.wait_for_device()

        main_success = self.forward_port(42690, 42690)

        if debug_mode:
            debug_success = self.reverse_port(5678, 5678)
            return main_success and debug_success

        return main_success


class DeviceConnection:
    def __init__(
            self,
            host: str = "127.0.0.1",
            port: int = 42690,
            debug_enabled: bool = False,
            debug_host: str = "127.0.0.1",
            debug_port: int = 5678,
            retry_delay: int = 2,
    ):
        self.host: str = host
        self.port: int = port
        self.debug_enabled: bool = debug_enabled
        self.debug_host: str = debug_host
        self.debug_port: int = debug_port
        self.retry_delay: int = retry_delay
        self.socket: Optional[socket.socket] = None
        self.connected: bool = False
        self.logger: logging.Logger = logging.getLogger("DeviceConnection")
        self.ping_thread: Optional[threading.Thread] = None
        self.running: bool = True

    def connect(self) -> bool:
        if self.connected and self.socket:
            return True

        attempt: int = 1
        while self.running:
            try:
                self.logger.info(f"Connecting to device (attempt {attempt})...")
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.host, self.port))
                self.connected = True
                self.logger.info("Connected to device")

                if self.debug_enabled:
                    self.stop_debugger()
                    self.logger.info("Sent stop_debugger message")
                    time.sleep(0.5)
                    self.setup_debugger()

                if not self.ping_thread or not self.ping_thread.is_alive():
                    self.start_ping_thread()

                return True
            except Exception as e:
                self.logger.error(f"Connection attempt {attempt} failed: {e}")
                if self.socket:
                    self.socket.close()
                    self.socket = None
                self.connected = False

                self.logger.info(f"Retrying in {self.retry_delay} seconds...")
                time.sleep(self.retry_delay)
                attempt += 1

        return False

    def disconnect(self):
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except Exception as e:
                self.logger.error(f"Error closing connection: {e}")
            finally:
                self.socket = None
                self.connected = False
                self.logger.info("Disconnected from device")

    def ping(self) -> bool:
        return self.send_message({"action": "ping"})

    def start_ping_thread(self):
        def ping_worker():
            while self.running and self.connected:
                try:
                    self.ping()
                    time.sleep(10)
                except Exception as e:
                    self.logger.error(f"Error in ping thread: {e}")
                    break

        self.ping_thread = threading.Thread(target=ping_worker, daemon=True)
        self.ping_thread.start()
        self.logger.debug("Ping thread started")

    def send_message(self, message: Dict[str, Any]) -> bool:
        if not self.connected and not self.connect():
            return False

        try:
            data = json.dumps(message).encode("utf-8")
            self.socket.sendall(data)
            self.logger.debug(f"Sent message: {message['action']}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to send message: {e}")
            self.disconnect()
            return self.connect() and self.send_message(message)

    def write_plugin(self, plugin_id: str, content: str) -> bool:
        return self.send_message(
            {"action": "write_plugin", "plugin_id": plugin_id, "content": content}
        )

    def reload_plugin(self, plugin_id: str) -> bool:
        return self.send_message({"action": "reload_plugin", "plugin_id": plugin_id})

    def stop_debugger(self) -> bool:
        return self.send_message(
            {
                "action": "stop_debugger",
            }
        )

    def setup_debugger(self) -> bool:
        return self.send_message(
            {
                "action": "start_debugger",
                "host": self.debug_host,
                "port": self.debug_port,
            }
        )


# copied from plugins manager
def parse_metadata(content: str) -> Optional[PluginMetadata]:
    logger = logging.getLogger("metadata")
    metadata = {}
    try:
        tree = ast.parse(content)
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                            isinstance(target, ast.Name)
                            and target.id.startswith("__")
                            and target.id.endswith("__")
                    ):
                        if isinstance(node.value, ast.Constant):
                            metadata[target.id] = node.value.value

        return PluginMetadata(
            id=metadata.get("__id__", ""),
            name=metadata.get("__name__", ""),
            description=metadata.get("__description__", ""),
            author=metadata.get("__author__", ""),
            min_version=metadata.get("__min_version__", ""),
        )
    except Exception as e:
        logger.error(f"Error parsing plugin metadata from file: {e}")
        return None


class FileMonitor:
    def __init__(self, connection: DeviceConnection):
        self.connection: DeviceConnection = connection
        self.logger: logging.Logger = logging.getLogger("FileMonitor")
        self.file_metadata: Dict[str, Tuple[float, Optional[PluginMetadata]]] = {}
        self.running: bool = True

    def add_files(self, filenames: List[str]):
        for filename in filenames:
            if not os.path.isfile(filename):
                self.logger.error(f"File '{filename}' not found - skipping")
                continue

            content, metadata = self._read_file_and_metadata(filename)
            if metadata is None or not metadata.id:
                self.logger.error(
                    f"File '{filename}' has no valid plugin ID - skipping"
                )
                continue

            self.file_metadata[filename] = (os.path.getmtime(filename), metadata)

            self._upload_file(filename, content, metadata.id)
            self.logger.info(
                f"Added file '{filename}' with plugin ID '{metadata.id}' for monitoring"
            )

    def _read_file_and_metadata(
            self, filename: str
    ) -> Tuple[str, Optional[PluginMetadata]]:
        try:
            with open(filename, "r") as f:
                content = f.read()

            metadata = parse_metadata(content)
            return content, metadata
        except Exception as e:
            self.logger.error(f"Error reading file '{filename}': {e}")
            return "", None

    def _upload_file(self, filename: str, content: str, plugin_id: str) -> bool:
        try:
            if self.connection.write_plugin(plugin_id, content):
                self.logger.info(f"Uploaded '{filename}' with plugin ID '{plugin_id}'")
                success = self.connection.reload_plugin(plugin_id)
                if success:
                    self.logger.info(f"Reloaded plugin '{plugin_id}'")
                else:
                    self.logger.warning(f"Failed to reload plugin '{plugin_id}'")
                return success
            self.logger.warning(f"Failed to upload '{filename}'")
            return False
        except Exception as e:
            self.logger.error(f"Error uploading file '{filename}': {e}")
            return False

    def start_monitoring(self):
        if not self.file_metadata:
            self.logger.warning("No valid files to monitor")
            return

        self.logger.info(f"Starting to monitor {len(self.file_metadata)} files")

        try:
            while self.running:
                time.sleep(1)
                self._check_for_changes()
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
        finally:
            self.connection.stop_debugger()
            self.connection.disconnect()

    def _check_for_changes(self):
        for filename, (last_modified, metadata) in list(self.file_metadata.items()):
            try:
                if not os.path.isfile(filename):
                    self.logger.warning(
                        f"File '{filename}' no longer exists - skipping check"
                    )
                    continue

                current_modified = os.path.getmtime(filename)
                if current_modified != last_modified:
                    self.logger.info(f"File '{filename}' changed")

                    content, new_metadata = self._read_file_and_metadata(filename)

                    if new_metadata is None or not new_metadata.id:
                        self.logger.warning(
                            f"Modified file '{filename}' has no valid plugin ID - skipping update"
                        )
                        self.file_metadata[filename] = (current_modified, metadata)
                        continue

                    self._upload_file(filename, content, new_metadata.id)

                    self.file_metadata[filename] = (current_modified, new_metadata)

            except FileNotFoundError:
                self.logger.error(f"File '{filename}' not found during check")
            except PermissionError:
                self.logger.error(f"Permission denied when accessing '{filename}'")
            except Exception as e:
                self.logger.error(f"Error checking file '{filename}': {e}")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Monitor plugins' changes and sync them to Android device."
    )
    parser.add_argument(
        "files", nargs="+", help="One or more files to monitor for changes"
    )
    parser.add_argument("--debug", action="store_true", help="Enable PyCharm debugger")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set the logging level",
    )
    return parser.parse_args()


def setup_logging(level: str):
    numeric_level: int = getattr(logging, level.upper(), None)
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    logging.basicConfig(level=numeric_level, format=log_format)


def main():
    args = parse_arguments()
    setup_logging(args.log_level)
    logger = logging.getLogger("main")

    valid_files = [f for f in args.files if os.path.isfile(f)]
    if not valid_files:
        logger.error("None of the specified files exist. Exiting.")
        sys.exit(1)

    adb_manager = AdbManager()
    if not adb_manager.setup_device(args.debug):
        logger.error("Failed to set up ADB connection. Exiting.")
        sys.exit(1)

    connection = DeviceConnection(debug_enabled=args.debug)
    if not connection.connect():
        logger.error("Failed to establish connection to device. Exiting.")
        sys.exit(1)

    monitor = FileMonitor(connection)
    monitor.add_files(args.files)

    logger.info(
        f"Monitoring {len(args.files)} files for changes. Press Ctrl+C to stop."
    )
    monitor.start_monitoring()


if __name__ == "__main__":
    main()
