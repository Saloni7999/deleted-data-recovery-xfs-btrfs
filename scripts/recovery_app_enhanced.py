
import tkinter as tk
from tkinter import filedialog
import subprocess
import hashlib
import csv
import os
import re
import time
from datetime import datetime

# Project paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_DIR = os.path.join(BASE_DIR, "reports")
RECOVERED_DIR = os.path.join(BASE_DIR, "recovered")

os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(RECOVERED_DIR, exist_ok=True)

# Experiment reference hashes
REFERENCE_HASHES = {
    "XFS": "5ea682a8aa9a1ef95621cf5169b759b4027567e93ede9dd50cc4a8f9928ece4e",
    "Btrfs": "e0dd7385bfce248713a6a328a233b09405986af0a9700cb5861fbccdef44a2af"
}

FILESYSTEM_DATA = {
    "XFS": {
        "evidence": "CONFIDENTIAL: XFS recovery experiment - test evidence.",
        "offset": 57344,
        "size": 55,
        "filename": "secret.txt",
        "output": os.path.join(RECOVERED_DIR, "xfs_secret_recovered.txt")
    },
    "Btrfs": {
        "evidence": "CONFIDENTIAL: Btrfs recovery experiment - test evidence.",
        "offset": 39271606,
        "size": 57,
        "filename": "secret.txt",
        "output": os.path.join(RECOVERED_DIR, "btrfs", "btrfs_secret_recovered.txt")
    }
}

CSV_FILE = os.path.join(REPORT_DIR, "application_recovery_results.csv")
REPORT_FILE = os.path.join(REPORT_DIR, "forensic_recovery_report.txt")

root = tk.Tk()
root.title("Deleted Data Recovery Tool")
root.geometry("800x650")

title = tk.Label(
    root,
    text="DELETED DATA RECOVERY TOOL",
    font=("Arial", 20, "bold")
)
title.pack(pady=25)

path_label = tk.Label(root, text="Forensic Image:")
path_label.pack(pady=10)

path_entry = tk.Entry(root, width=70)
path_entry.pack(pady=5)


def select_image():
    selected_file = filedialog.askopenfilename(
        title="Select Forensic Disk Image"
    )
    if selected_file:
        path_entry.delete(0, tk.END)
        path_entry.insert(0, selected_file)


select_btn = tk.Button(
    root, text="SELECT IMAGE", width=20, command=select_image
)
select_btn.pack(pady=15)

result_label = tk.Label(
    root,
    text="Status: Waiting for analysis...",
    font=("Arial", 12)
)
result_label.pack(pady=15)

analyze_btn = tk.Button(root, text="ANALYZE IMAGE", width=20)
analyze_btn.pack(pady=10)

scan_btn = tk.Button(root, text="FORENSIC SCAN", width=20)
scan_btn.pack(pady=10)

scan_result = tk.Text(root, height=15, width=90)
scan_result.pack(pady=5)

recover_btn = tk.Button(root, text="RECOVER DELETED FILE", width=25)
recover_btn.pack(pady=10)

# Stores the latest scan information
last_scan = {}


def detect_filesystem(image):
    if not os.path.isfile(image):
        raise FileNotFoundError("Selected image does not exist.")

    result = subprocess.run(
        ["file", image],
        capture_output=True,
        text=True,
        check=True
    )

    output = result.stdout.lower()

    if "btrfs" in output:
        return "Btrfs"
    elif "xfs" in output:
        return "XFS"

    return None


def analyze_image():
    image = path_entry.get().strip()

    if not image:
        result_label.config(text="Status: Please select an image.")
        return

    try:
        filesystem = detect_filesystem(image)

        if filesystem:
            result_label.config(
                text=f"Filesystem Detected: {filesystem}"
            )
        else:
            result_label.config(
                text="Filesystem: Unknown / Unsupported"
            )

    except Exception as error:
        result_label.config(text=f"Error: {error}")


def forensic_scan():
    global last_scan

    image = path_entry.get().strip()
    scan_result.delete("1.0", tk.END)

    if not image:
        scan_result.insert(tk.END, "Please select an image first.\n")
        return

    try:
        filesystem = detect_filesystem(image)

        if filesystem is None:
            scan_result.insert(tk.END, "Unsupported filesystem.\n")
            return

        config = FILESYSTEM_DATA[filesystem]

        scan_result.insert(
            tk.END, f"{filesystem.upper()} FORENSIC SCAN\n"
        )
        scan_result.insert(tk.END, "=" * 30 + "\n\n")

        start_time = time.perf_counter()

        result = subprocess.run(
            [
                "grep", "-aobF",
                config["evidence"],
                image
            ],
            capture_output=True,
            text=True
        )

        scan_time = time.perf_counter() - start_time

        if result.returncode not in (0, 1):
            raise RuntimeError(result.stderr.strip() or "Scan failed.")

        matches = [
            line for line in result.stdout.splitlines() if line.strip()
        ]

        scan_result.insert(
            tk.END, f"Scan time: {scan_time:.6f} seconds\n"
        )
        scan_result.insert(
            tk.END, f"Matching occurrences: {len(matches)}\n\n"
        )

        if matches:
            scan_result.insert(
                tk.END, "Matching evidence found:\n"
            )
            for match in matches:
                scan_result.insert(tk.END, match + "\n")
        else:
            scan_result.insert(
                tk.END, "No matching evidence found.\n"
            )

        # The known experimental offset is used for recovery.
        expected_offset = config["offset"]
        selected_match = any(
            line.split(":", 1)[0].isdigit()
            and int(line.split(":", 1)[0]) == expected_offset
            for line in matches
        )

        last_scan = {
            "image": image,
            "filesystem": filesystem,
            "scan_time": scan_time,
            "occurrences": len(matches),
            "target_found": selected_match
        }

        scan_result.insert(
            tk.END,
            "\nExpected experimental offset: "
            f"{expected_offset}\n"
        )
        scan_result.insert(
            tk.END,
            "Expected offset found: "
            f"{'Yes' if selected_match else 'No'}\n"
        )

    except Exception as error:
        last_scan = {}
        scan_result.insert(tk.END, f"Scan error: {error}\n")


def append_csv(row):
    fields = [
        "Timestamp",
        "Filesystem",
        "Image",
        "Detection",
        "Occurrences",
        "Offset",
        "Scan_Time_Seconds",
        "Recovery_Time_Seconds",
        "Recovered_Size_Bytes",
        "SHA256_Match",
        "Recovery_Status"
    ]

    file_exists = os.path.isfile(CSV_FILE)

    with open(CSV_FILE, "a", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)

        if not file_exists or os.path.getsize(CSV_FILE) == 0:
            writer.writeheader()

        writer.writerow(row)


def append_report(filesystem, image, output_file, offset,
                  size, recovery_time, duration, file_hash,
                  hash_match, status):

    with open(REPORT_FILE, "a") as report:
        report.write("\n\nDELETED DATA RECOVERY - FORENSIC REPORT\n")
        report.write("=======================================\n")
        report.write(f"Timestamp: {recovery_time}\n")
        report.write(f"Filesystem: {filesystem}\n")
        report.write(f"Source image: {image}\n")
        report.write(f"Original filename: secret.txt\n")
        report.write(f"Recovered file: {output_file}\n")
        report.write(f"Data offset: {offset}\n")
        report.write(f"Recovered size: {size} bytes\n")
        report.write(f"Recovery duration: {duration:.6f} seconds\n")
        report.write(f"SHA-256: {file_hash}\n")
        report.write(f"Reference hash match: {hash_match}\n")
        report.write(f"Recovery status: {status}\n")


def recover_deleted_file():
    global last_scan

    image = path_entry.get().strip()

    if not image:
        scan_result.insert(tk.END, "\nPlease select an image first.\n")
        return

    try:
        filesystem = detect_filesystem(image)

        if filesystem is None:
            scan_result.insert(tk.END, "\nUnsupported filesystem.\n")
            return

        # Require a successful scan of the same image first.
        if (
            not last_scan
            or last_scan.get("image") != image
            or last_scan.get("filesystem") != filesystem
        ):
            scan_result.insert(
                tk.END,
                "\nPlease run FORENSIC SCAN on this image first.\n"
            )
            return

        if not last_scan["target_found"]:
            scan_result.insert(
                tk.END,
                "\nExpected evidence was not found at the "
                "known experimental offset. Recovery stopped.\n"
            )
            return

        config = FILESYSTEM_DATA[filesystem]
        offset = config["offset"]
        expected_size = config["size"]
        output_file = config["output"]

        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        start_time = time.perf_counter()

        result = subprocess.run(
            [
                "dd",
                f"if={image}",
                f"of={output_file}",
                "bs=1",
                f"skip={offset}",
                f"count={expected_size}"
            ],
            capture_output=True,
            text=True
        )

        recovery_duration = time.perf_counter() - start_time
        recovery_timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip() or "dd recovery command failed."
            )

        if not os.path.isfile(output_file):
            raise RuntimeError("Recovered output file was not created.")

        recovered_size = os.path.getsize(output_file)

        if recovered_size != expected_size:
            raise RuntimeError(
                f"Size validation failed: expected {expected_size} "
                f"bytes, got {recovered_size} bytes."
            )

        with open(output_file, "rb") as recovered:
            file_hash = hashlib.sha256(recovered.read()).hexdigest()

        hash_match = (
            file_hash == REFERENCE_HASHES[filesystem]
        )

        status = "SUCCESS" if hash_match else "HASH_MISMATCH"

        append_report(
            filesystem,
            image,
            output_file,
            offset,
            recovered_size,
            recovery_timestamp,
            recovery_duration,
            file_hash,
            "Yes" if hash_match else "No",
            status
        )

        append_csv({
            "Timestamp": recovery_timestamp,
            "Filesystem": filesystem,
            "Image": image,
            "Detection": "Yes",
            "Occurrences": last_scan["occurrences"],
            "Offset": offset,
            "Scan_Time_Seconds": f'{last_scan["scan_time"]:.6f}',
            "Recovery_Time_Seconds": f"{recovery_duration:.6f}",
            "Recovered_Size_Bytes": recovered_size,
            "SHA256_Match": "Yes" if hash_match else "No",
            "Recovery_Status": status
        })

        scan_result.insert(
            tk.END,
            f"\n{filesystem.upper()} RECOVERY RESULT\n"
            "==============================\n"
        )
        scan_result.insert(
            tk.END, f"Recovered file: {output_file}\n"
        )
        scan_result.insert(
            tk.END, f"Data offset: {offset}\n"
        )
        scan_result.insert(
            tk.END, f"Recovered size: {recovered_size} bytes\n"
        )
        scan_result.insert(
            tk.END,
            f"Recovery time: {recovery_duration:.6f} seconds\n"
        )
        scan_result.insert(
            tk.END, f"Recovery timestamp: {recovery_timestamp}\n"
        )
        scan_result.insert(
            tk.END, f"SHA-256: {file_hash}\n"
        )
        scan_result.insert(
            tk.END,
            f"Reference hash match: {'Yes' if hash_match else 'No'}\n"
        )
        scan_result.insert(
            tk.END, f"Recovery status: {status}\n"
        )
        scan_result.insert(
            tk.END, f"CSV results: {CSV_FILE}\n"
        )
        scan_result.insert(
            tk.END, f"Forensic report: {REPORT_FILE}\n"
        )

    except Exception as error:
        scan_result.insert(
            tk.END, f"\nRecovery error: {error}\n"
        )


analyze_btn.config(command=analyze_image)
scan_btn.config(command=forensic_scan)
recover_btn.config(command=recover_deleted_file)

root.mainloop()
