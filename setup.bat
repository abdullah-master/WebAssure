REM filepath: c:\Users\laxmi\OneDrive\Desktop\Sem 6\ZapNik_Scanner-main\setup.bat
@echo off
echo Setting up ZapNik Scanner...


echo Installing required Python packages...
pip install pymongo flask python-dotenv



echo Starting the application...
python app.py