import os
import requests
import sys

DB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
DB_FILE = "GeoLite2-City.mmdb"

def download_database():
    print(f"[*] Checking for offline geolocation database ({DB_FILE})...")
    if os.path.exists(DB_FILE):
        print(f"[+] {DB_FILE} is already present! Initialization complete.")
        return

    print(f"[*] Downloading {DB_FILE} (approx. 50-70MB)...")
    print(f"[*] Fetching from global mirror...")
    
    try:
        response = requests.get(DB_URL, stream=True)
        response.raise_for_status()
        
        total_size = int(response.headers.get('content-length', 0))
        block_size = 1024 * 1024 # 1 Megabyte
        downloaded = 0
        
        with open(DB_FILE, 'wb') as f:
            for data in response.iter_content(block_size):
                f.write(data)
                downloaded += len(data)
                if total_size:
                    done = int(50 * downloaded / total_size)
                    sys.stdout.write(f"\r[{'=' * done}{' ' * (50-done)}] {downloaded/(1024*1024):.1f} MB")
                    sys.stdout.flush()
                    
        print("\n[+] Download completed successfully!")
    except Exception as e:
        print(f"\n[-] Error downloading the database: {e}")
        print("[-] Please download it manually and place 'GeoLite2-City.mmdb' inside the KAVACH directory.")
        sys.exit(1)

if __name__ == "__main__":
    download_database()
