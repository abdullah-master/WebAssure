import os
import requests
from pathlib import Path

def setup_fonts():
    print("[*] Setting up fonts...")
    
    # Create fonts directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    fonts_dir = os.path.join(current_dir, 'fonts')
    os.makedirs(fonts_dir, exist_ok=True)
    
    # Font URLs - Using the dejavu-fonts release files
    fonts = {
        'DejaVuSansCondensed.ttf': 'https://github.com/dejavu-fonts/dejavu-fonts/releases/download/version_2_37/dejavu-fonts-ttf-2.37.zip',
        'DejaVuSansCondensed-Bold.ttf': 'https://github.com/dejavu-fonts/dejavu-fonts/releases/download/version_2_37/dejavu-fonts-ttf-2.37.zip'
    }
    
    success = True
    import zipfile
    import tempfile
    
    # Download and extract fonts from zip
    try:
        print("[*] Downloading DejaVu fonts...")
        response = requests.get(list(fonts.values())[0], allow_redirects=True)
        response.raise_for_status()
        
        # Save and extract zip
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_file:
            temp_file.write(response.content)
            temp_file.flush()
            
            with zipfile.ZipFile(temp_file.name, 'r') as zip_ref:
                # Extract specific font files
                for zip_info in zip_ref.filelist:
                    if zip_info.filename.endswith(tuple(fonts.keys())):
                        zip_info.filename = os.path.basename(zip_info.filename)
                        zip_ref.extract(zip_info, fonts_dir)
                        print(f"[+] Successfully extracted {zip_info.filename}")
        
        os.unlink(temp_file.name)
        print("[+] Font setup complete")
        
    except Exception as e:
        print(f"[-] Error setting up fonts: {e}")
        success = False
        print("[-] Font setup encountered errors")
    
    return success

if __name__ == "__main__":
    setup_fonts()
