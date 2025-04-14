import os
import requests
from pathlib import Path

def setup_fonts():
    print("[*] Setting up fonts...")
    
    # Create fonts directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    fonts_dir = os.path.join(current_dir, 'fonts')
    os.makedirs(fonts_dir, exist_ok=True)
    
    # Font URLs - Updated to use GitHub raw content URLs
    fonts = {
        'DejaVuSansCondensed.ttf': 'https://raw.githubusercontent.com/dejavu-fonts/dejavu-fonts/master/ttf/DejaVuSansCondensed.ttf',
        'DejaVuSansCondensed-Bold.ttf': 'https://raw.githubusercontent.com/dejavu-fonts/dejavu-fonts/master/ttf/DejaVuSansCondensed-Bold.ttf'
    }
    
    success = True
    for font_name, url in fonts.items():
        font_path = os.path.join(fonts_dir, font_name)
        if not os.path.exists(font_path):
            try:
                print(f"[*] Downloading {font_name}...")
                response = requests.get(url, allow_redirects=True)
                response.raise_for_status()
                
                with open(font_path, 'wb') as f:
                    f.write(response.content)
                print(f"[+] Successfully downloaded {font_name}")
            except Exception as e:
                print(f"[-] Error downloading {font_name}: {e}")
                success = False
        else:
            print(f"[+] Font {font_name} already exists")
    
    if success:
        print("[+] Font setup complete")
    else:
        print("[-] Font setup encountered errors")
    return success

if __name__ == "__main__":
    setup_fonts()
