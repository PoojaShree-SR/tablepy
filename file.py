import os
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class FileIntegrityMonitor:

    def __init__(self):
        self.file_hashes = {}

    # Function to compute file hash using SHA-256
    def compute_file_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    # Initialize hashes of all files in the directory
    def initialize_file_hashes(self, directory_path):
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.isfile(file_path):
                    self.file_hashes[file_path] = self.compute_file_hash(file_path)
        print("Initial file hashes stored.")

    # Monitor files for changes using watchdog
    def monitor_files(self, directory_path):
        event_handler = FileChangeHandler(self)
        observer = Observer()
        observer.schedule(event_handler, directory_path, recursive=True)
        observer.start()
        print(f"Monitoring directory: {directory_path}")

        try:
            while True:
                pass  # Keep the script running
        except KeyboardInterrupt:
            observer.stop()
        observer.join()

class FileChangeHandler(FileSystemEventHandler):

    def __init__(self, monitor):
        self.monitor = monitor

    def on_created(self, event):
        if not event.is_directory:
            print(f"File created: {event.src_path}")
            self.monitor.file_hashes[event.src_path] = self.monitor.compute_file_hash(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            print(f"File deleted: {event.src_path}")
            self.monitor.file_hashes.pop(event.src_path, None)

    def on_modified(self, event):
        if not event.is_directory:
            print(f"File modified: {event.src_path}")
            new_hash = self.monitor.compute_file_hash(event.src_path)
            old_hash = self.monitor.file_hashes.get(event.src_path)

            if old_hash and new_hash != old_hash:
                print(f"File integrity compromised: {event.src_path}")
            self.monitor.file_hashes[event.src_path] = new_hash

if __name__ == "__main__":
    monitor = FileIntegrityMonitor()

    # Replace the directory path with the one you want to monitor
    directory_path = r"C:\Users\DELL\fileintegrity"

    monitor.initialize_file_hashes(directory_path)
    monitor.monitor_files(directory_path)
