import hashlib
import os
import shutil
import psutil
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

# Constants
MALICIOUS_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f", # EICAR test file hash
}

# Default quarantine folder (initial value)
QUARANTINE_FOLDER = "./quarantine"


# Calculate MD5 hash of a file
def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


# Scan directory for malicious files
def scan_directory(directory):
    detected_files = []
    total_files = 0
    start_time = time.time()  # Start time for scan

    for root, _, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            file_hash = calculate_md5(file_path)
            total_files += 1
            # Debug output to verify detected files
            print(f"Scanning file: {file_path}, MD5 Hash: {file_hash}")

            if file_hash in MALICIOUS_HASHES:
                print(f"Detected malicious file: {file_path}")
                detected_files.append(file_path)

    end_time = time.time()  # End time for scan
    scan_time = end_time - start_time
    scan_speed = total_files / scan_time if scan_time > 0 else 0  # Files per second
    return detected_files, scan_time, scan_speed


# Quarantine the detected malicious file
def quarantine_file(file_path, quarantine_folder):
    if not os.path.exists(quarantine_folder):
        os.makedirs(quarantine_folder)  # Create the quarantine folder if it doesn't exist

    try:
        shutil.move(file_path, quarantine_folder)  # Move the file to quarantine folder
        return True
    except Exception as e:
        print(f"Error while quarantining {file_path}: {e}")
        return False


# Delete the detected malicious file
def delete_file(file_path):
    try:
        os.remove(file_path)  # Delete the file
        return True
    except Exception as e:
        print(f"Error while deleting {file_path}: {e}")
        return False


# Performance monitoring function
def get_system_performance():
    cpu_usage = psutil.cpu_percent(interval=0.5)
    memory_info = psutil.virtual_memory()
    return cpu_usage, memory_info.percent


# GUI Class
class AntiMalwareGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Anti-Malware Program")
        self.root.geometry("700x500")

        # User-defined quarantine folder path
        self.folder_path = tk.StringVar()
        self.quarantine_folder = tk.StringVar(value=QUARANTINE_FOLDER)

        # Folder path selection
        tk.Label(root, text="Select folder to scan:").pack(pady=5)
        path_frame = tk.Frame(root)
        path_frame.pack(pady=5)

        self.path_entry = tk.Entry(path_frame, textvariable=self.folder_path, width=50)
        self.path_entry.pack(side=tk.LEFT, padx=5)

        browse_button = tk.Button(path_frame, text="Browse", command=self.browse_folder)
        browse_button.pack(side=tk.LEFT)

        # Quarantine folder path
        tk.Label(root, text="Select quarantine folder:").pack(pady=5)
        path_frame = tk.Frame(root)
        path_frame.pack(pady=5)

        self.quarantine_entry = tk.Entry(path_frame, textvariable=self.quarantine_folder, width=50)
        self.quarantine_entry.pack(side=tk.LEFT, padx=5)

        browse_quarantine_button = tk.Button(path_frame, text="Browse", command=self.browse_quarantine)
        browse_quarantine_button.pack(side=tk.LEFT)

        # Scan button
        self.scan_button = tk.Button(root, text="Scan Folder", command=self.scan_files)
        self.scan_button.pack(pady=10)

        # Quarantine button
        self.quarantine_button = tk.Button(root, text="Quarantine Malicious Files", command=self.quarantine_files, state=tk.DISABLED)
        self.quarantine_button.pack(pady=5)

        # Delete button
        self.delete_button = tk.Button(root, text="Delete Malicious Files", command=self.delete_files, state=tk.DISABLED)
        self.delete_button.pack(pady=5)

        # Results display
        self.result_text = scrolledtext.ScrolledText(root, width=80, height=15)
        self.result_text.pack(pady=10)

        self.detected_files = []  # List to store detected malicious files

    # Browse and select folder to scan
    def browse_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.folder_path.set(folder_selected)

    # Browse and select quarantine folder
    def browse_quarantine(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.quarantine_folder.set(folder_selected)

    # Scan files in the folder
    def scan_files(self):
        directory = self.folder_path.get()
        if not directory:
            messagebox.showwarning("Warning", "Please select a folder first!")
            return

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Scanning folder: {directory}...\n")

        # Perform scan and get performance metrics
        detected_files, scan_time, scan_speed = scan_directory(directory)

        self.detected_files = detected_files  # Save detected files

        if detected_files:
            self.result_text.insert(tk.END, "Detected malicious files:\n")
            for file_path in detected_files:
                self.result_text.insert(tk.END, f"{file_path}\n")
            self.quarantine_button.config(state=tk.NORMAL)  # Enable quarantine button
            self.delete_button.config(state=tk.NORMAL)  # Enable delete button
        else:
            self.result_text.insert(tk.END, "No malicious files detected.\n")
            self.quarantine_button.config(state=tk.DISABLED)
            self.delete_button.config(state=tk.DISABLED)

        # Display scan time, speed, and performance
        self.result_text.insert(tk.END, f"\nScan completed in {scan_time:.2f} seconds.\n")
        self.result_text.insert(tk.END, f"Scan speed: {scan_speed:.2f} files per second.\n")

        # Display CPU and memory usage
        cpu_usage, memory_usage = get_system_performance()
        self.result_text.insert(tk.END, f"CPU Usage: {cpu_usage}%\n")
        self.result_text.insert(tk.END, f"Memory Usage: {memory_usage}%\n")

    # Quarantine malicious files
    def quarantine_files(self):
        if not self.detected_files:
            messagebox.showinfo("Info", "No malicious files to quarantine.")
            return

        quarantine_folder = self.quarantine_folder.get()
        self.result_text.insert(tk.END, "\nQuarantining malicious files...\n")
        for file_path in self.detected_files:
            if quarantine_file(file_path, quarantine_folder):
                self.result_text.insert(tk.END, f"Quarantined: {file_path}\n")
            else:
                self.result_text.insert(tk.END, f"Failed to quarantine: {file_path}\n")

        self.quarantine_button.config(state=tk.DISABLED)
        messagebox.showinfo("Completed", "Malicious files have been quarantined.")

    # Delete malicious files
    def delete_files(self):
        if not self.detected_files:
            messagebox.showinfo("Info", "No malicious files to delete.")
            return

        self.result_text.insert(tk.END, "\nDeleting malicious files...\n")
        for file_path in self.detected_files:
            if delete_file(file_path):
                self.result_text.insert(tk.END, f"Deleted: {file_path}\n")
            else:
                self.result_text.insert(tk.END, f"Failed to delete: {file_path}\n")

        self.delete_button.config(state=tk.DISABLED)
        messagebox.showinfo("Completed", "Malicious files have been deleted.")


# Main program
if __name__ == "__main__":
    root = tk.Tk()
    app = AntiMalwareGUI(root)
    root.mainloop()
