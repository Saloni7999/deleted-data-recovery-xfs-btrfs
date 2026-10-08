
import os
import subprocess

def detect_filesystem(image_path):
    """
    Detect whether the disk image is XFS or Btrfs.
    """

    try:
       result = subprocess.run(
          ["blkid", "-o", "value", "-s", "TYPE", image_path],
          capture_output=True,
          text=True
        )

       filesystem = result.stdout.strip().lower()

       if filesystem == "xfs":
           return "XFS"
       elif filesystem == "btrfs":
           return "Btrfs"
       else:
           return "Unknown"

    except Exception as e:
        print("Error detecting filesystem:", e)
        return "Unknown"


def main():
    print("=" * 60)
    print("DELETED DATA RECOVERY & METEDATA ANALYSIS TOOL")
    print("=" * 60)
    print()

    image_path = input("Enter disk image path: ").strip()

    if not os.path.exists(image_path):
        print("Error: Image file does not exist.")
        return

    print("Analyzing image...")

    filesystem = detect_filesystem(image_path)

    print("Filesystem detected:", filesystem)


if __name__ == "__main__":
    main()
