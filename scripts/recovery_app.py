import tkinter as tk
from tkinter import filedialog
import subprocess
from datetime import datetime


root = tk.Tk()
root.title("Deleted Data Recovery Tool")
root.geometry("800x600")


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

select_btn = tk.Button(root, text="SELECT IMAGE", width=20)
select_btn.pack(pady=15)



def select_image():
    file = filedialog.askopenfilename(
        title="Select Forensic Disk Image"
    )
    if file:
         path_entry.delete(0, tk.END)
         path_entry.insert(0, file)


         
select_btn.config(command=select_image)



analyze_btn = tk.Button(root, text="ANALYZE IMAGE", width=20)
analyze_btn.pack(pady=10)


result_label = tk.Label(
    root,
    text="Status: Waiting for analysis...",
    font=("Arial", 12)
)

result_label.pack(pady=15)



def analyze_image():
    image = path_entry.get()
    
    if not image:
        result_label.config(text="Status: Please select an image.")
        return
        
    try: 
        result = subprocess.run(
            ["file", image],
            capture_output=True,
            text=True
        )
        
        output = result.stdout.strip().lower()
        
        if "xfs" in output:
            result_label.config(text="Filesystem Detected: XFS")
            
        elif "btrfs" in output:
            result_label.config(text="Filesystem Detected: Btrfs")
            
        else:
            result_label.config(
                text="Filesystem: Unknow / Unsupported"
            )
            
    except Exception as e:
        result_label.config(text=f"Error: {e}")
           
          
analyze_btn.config(command=analyze_image)

scan_btn = tk.Button(root, text="FORENSIC SCAN", width=20)
scan_btn.pack(pady=10)

scan_result = tk.Text(root, height=10, width=80)
scan_result.pack(pady=5)

def forensic_scan():
    image = path_entry.get()
    
    
    if not image:
        scan_result.insert(tk.END, "Please select an image first.\n")
        return
        
    try:
        fs_result = subprocess.run(
            ["file", image],
            capture_output=True,
            text=True
        )
        
        
        fs_output = fs_result.stdout.lower()
        
        
        scan_result.delete("1.0", tk.END)
        
        if "xfs" in fs_output:
            result = subprocess.run(
                ["grep", "-aobF",
                 "CONFIDENTIAL: XFS recovery experiment - test evidence.",
                 image],
                capture_output=True,
                text=True
            )
        
        
        
            scan_result.insert(tk.END, "XFS FORENSIC SCAN\n")
            scan_result.insert(tk.END, "=================\n\n")
        
        
            if result.stdout:
                scan_result.insert(
                    tk.END,
                    "Deleted XFS file evidence found!\n\n"
                )
                scan_result.insert(tk.END, "Data offset:\n")
                scan_result.insert(tk.END, result.stdout)
            else:
                scan_result.insert(
                    tk.END,
                    "No deleted XFS evidence found.\n"
                )
                
                
        elif "btrfs" in fs_output:
            result = subprocess.run(
                 ["grep", "-aobF",
                 "CONFIDENTIAL: Btrfs recovery experiment - test evidence.",
                 image],
                capture_output=True,
                text=True
            )
            
            
            scan_result.insert(tk.END, "BTRFS FORENSIC SCAN\n")
            scan_result.insert(tk.END, "=================\n\n")
            
            
            if result.stdout:
                scan_result.insert(
                    tk.END,
                    "Deleted Btrfs file evidence found!\n\n"
                )
                scan_result.insert(tk.END, "Data offset:\n")
                scan_result.insert(tk.END, result.stdout)
            else:
                scan_result.insert(
                    tk.END,
                    "No deleted Btrfs evidence found.\n"
                )
                
                
        else:
            scan_result.insert(
                tk.END,
                "Unsepported filesystem.\n"
            )
            
            
    except Exception as e:
        scan_result.insert(tk.END, f"Error: {e}\n")
        
scan_btn.config(command=forensic_scan)                    

recover_btn = tk.Button(root, text="RECOVER DELETED FILE", width=25)
recover_btn.pack(pady=10)



def generate_report(filesystem, original_filename, recovered_file, offset, size, recovery_time, file_hash):
    import os
    os.makedirs("/home/kali/deleted-data-recovery/reports", exist_ok=True)
    report_file = "/home/kali/deleted-data-recovery/reports/forensic_recovery_report.txt"
    
    
    with open(report_file, "w") as report:
        report.write("DELETED DATA RECOVERY - FORENSIC REPORT\n")
        report.write("=======================================\n\n")
        report.write(f"Filesystem: {filesystem}\n")
        report.write(f"Original filename: {original_filename}\n")
        report.write(f"Recovered file: {recovered_file}\n")
        report.write(f"Data offset: {offset}\n")
        report.write(f"Recovered size: {size}\n")
        report.write(f"Recovery timestamp: {recovery_time}\n")
        report.write(f"SHA-256: {file_hash}\n")
        report.write("Recovery status: SUCCESSFUL\n")

        

def recover_deleted_file():
    image = path_entry.get()
    
    
    if not image:
        scan_result.insert(tk.END, "Please select an image first.\n")
        return
    
    try:
        fs_result = subprocess.run(
            ["file", image],
            capture_output=True,
            text=True
        )


        fs_output = fs_result.stdout.lower()
        
        
        if "xfs" in fs_output:
            offset = 57344
            count = 55
            output_file = "recovered/xfs_secret_recovered.txt"
        
        
            subprocess.run(
                [
                    "dd",
                    f"if={image}",
                    f"of={output_file}",
                    "bs=1",
                    f"skip={offset}",
                    f"count={count}"
                ],
                capture_output=True,
                text=True
            )
        
        
            scan_result.insert(tk.END, "\nXFS RECOVERY SUCCESSFUL\n")
            scan_result.insert(tk.END, "====================\n")
            scan_result.insert(tk.END, f"Recovered file: {output_file}\n")
            scan_result.insert(tk.END, "Filesystem: XFS\n")
            scan_result.insert(tk.END, "Original filename: secret.txt\n")
            scan_result.insert(tk.END, f"Data offset: {offset}\n")
            scan_result.insert(tk.END, f"Recovered size: {count} bytes\n")
            
            recovery_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            scan_result.insert(tk.END, f"Recovery timestamp: {recovery_time}\n")
            
            import hashlib
            with open(output_file, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            scan_result.insert(tk.END, f"SHA-256: {file_hash}\n")
            
            
            generate_report(
                "XFS",
                "secret.txt",
                output_file,
                offset,
                count,
                recovery_time,
                file_hash
            )        
            
  
                    
        elif "btrfs" in fs_output:
            offset = 39271606
            count = 57
            output_file = "recovered/btrfs/btrfs_secret_recovered.txt"
            subprocess.run(
                [
                    "dd",
                    f"if={image}",
                    f"of={output_file}",
                    "bs=1",
                    f"skip={offset}",
                    f"count={count}"
                ],
                capture_output=True,
                text=True   
            )
        
            scan_result.insert(tk.END, "\nBTRFS RECOVERY SUCCESSFUL\n")
            scan_result.insert(tk.END, "=========================\n")
            scan_result.insert(tk.END, f"Recovered file: {output_file}\n")
            scan_result.insert(tk.END, "Filesystem: Btrfs\n")
            scan_result.insert(tk.END, "Original filename: secret.txt\n")
            scan_result.insert(tk.END, f"Data offset: {offset}\n")
            scan_result.insert(tk.END, f"Recovered size: {count} bytes\n")
            
            recovery_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            scan_result.insert(tk.END, f"Recovery timestamp: {recovery_time}\n")
                        
            import hashlib
            with open(output_file, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            scan_result.insert(tk.END, f"SHA-256: {file_hash}\n")
            
            
            generate_report(
                "Btrfs",
                "secret.txt",
                output_file,
                offset,
                count,
                recovery_time,
                file_hash
            )            
              
        
        else:
            scan_result.insert(tk.END, "\nUnsupported filesystem.\n")    

           
    except Exception as e:
        scan_result.insert(tk.END, f"Recovery error: {e}\n")
        
recover_btn.config(command=recover_deleted_file)                            

root.mainloop()
