from datetime import datetime
import json
import os
import time
import requests
from bson.objectid import ObjectId
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_from_directory, abort, send_file
from scan import run_nikto, run_owasp_zap, save_results, ZAP_ADDRESS, ZAP_PORT
from email_script import send_email
from db_operations import DatabaseHandler
from pdf_generator import generate_pdf_report
from threaded_scanner import ThreadedScanner

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

def check_zap_connection():
    """Check if ZAP GUI is running"""
    try:
        response = requests.get(f'http://{ZAP_ADDRESS}:{ZAP_PORT}')
        print("[+] Connected to ZAP GUI")
        return True
    except requests.exceptions.ConnectionError:
        print("[-] Could not connect to ZAP. Please ensure ZAP GUI is running")
        return False

# Check ZAP connection when the application starts
if not check_zap_connection():
    print("[-] Warning: ZAP is not running. Please start ZAP GUI first")

@app.route("/", methods=["GET"])
def landing():
    try:
        db_handler = DatabaseHandler()
        reports = db_handler.get_scan_history()
        return render_template("landing.html", reports=reports)
    except Exception as e:
        return render_template("landing.html", error=str(e))

@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "POST":
        try:
            target_url = request.form.get("target_url").strip()
            if not target_url.startswith(("http://", "https://")):
                target_url = f"http://{target_url}"

            # Get scan configuration
            scan_duration = request.form.get("scan_duration", "standard")
            selected_modules = request.form.getlist("modules[]")
            
            # Get selected tests
            zap_tests = {
                'xss': 'xss' in request.form.getlist("zap_tests[]"),
                'sqli': 'sqli' in request.form.getlist("zap_tests[]"),
                'auth_issues': 'auth_issues' in request.form.getlist("zap_tests[]"),
                'headers': 'headers' in request.form.getlist("zap_tests[]")
            }
            
            nikto_tests = {
                'sqli': 'sqli' in request.form.getlist("nikto_tests[]"),
                'headers': 'headers' in request.form.getlist("nikto_tests[]"),
                'ssl': 'ssl' in request.form.getlist("nikto_tests[]"),
                'auth': 'auth' in request.form.getlist("nikto_tests[]")
            }

            # Create unique output directory for this scan
            timestamp = int(time.time())
            file_paths = {
                'nikto_output': os.path.join("output", f"nikto_{timestamp}.json"),
                'zap_output': os.path.join("output", f"zap_{timestamp}.json"),
                'combined_output': os.path.join("output", f"combined_{timestamp}.json")
            }

            # Configure scanner with selected modules
            scanner = ThreadedScanner()
            
            # Run scan with configuration
            results = scanner.run_concurrent_scan(
                target_url=target_url,
                file_paths=file_paths,
                nikto_tuning="-Tuning 1" if 'nikto' in selected_modules else "",
                zap_options={
                    "enabled": 'zap' in selected_modules,
                    "tests": zap_tests,
                    "duration": scan_duration
                }
            )

            # Save results and get scan ID
            saved_results = save_results(
                target_url,
                results.get('nikto', {}),
                results.get('zap', {}),
                file_paths
            )

            if not saved_results:
                raise Exception("Failed to save scan results")

            if isinstance(saved_results, dict):
                scan_id = saved_results.get('scan_id')
            else:
                scan_id = str(saved_results)

            if not scan_id:
                raise Exception("No scan ID received")

            # Return JSON for AJAX requests
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'status': 'success',
                    'redirect_url': url_for('view_report', report_id=scan_id)
                })

            # Regular form submission redirect
            return redirect(url_for('view_report', report_id=scan_id))

        except Exception as e:
            error_msg = str(e)
            print(f"[-] Scan error: {error_msg}")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error': error_msg}), 500
            return render_template("main.html", error=error_msg)

    return render_template("main.html")

@app.route("/api/report/<report_id>")
def get_report_data(report_id):
    try:
        db_handler = DatabaseHandler()
        report = db_handler.get_report_by_id(report_id)
        if report:
            report['_id'] = str(report['_id'])  # Convert ObjectId to string
            return jsonify(report)
        return jsonify({"error": "Report not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/report/<report_id>")
def view_report(report_id):
    try:
        db_handler = DatabaseHandler()
        report = db_handler.get_report_by_id(report_id)
        if report:
            return render_template("result.html", report=report)
        return "Report not found", 404
    except Exception as e:
        return str(e), 500

@app.route("/download-pdf/<report_id>")
def download_pdf(report_id):
    try:
        report_type = request.args.get('type', 'complete')
        
        # Convert string report_id to ObjectId
        from bson.objectid import ObjectId
        try:
            report_id_obj = ObjectId(report_id)
        except Exception as e:
            print(f"Invalid report ID format: {report_id}")
            abort(400, description="Invalid report ID format")
        
        db_handler = DatabaseHandler()
        report = db_handler.get_report_by_id(report_id)
        
        if not report:
            print(f"Report not found: {report_id}")
            abort(404, description="Report not found")
        
        # Create output directory if it doesn't exist
        output_dir = os.path.join(os.path.dirname(__file__), 'output', 'reports')
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate unique filename
        timestamp = int(time.time())
        output_path = os.path.join(output_dir, f'report_{report_id}_{timestamp}.pdf')
        
        success = generate_pdf_report(report, output_path, report_type)
        if not success:
            print("Failed to generate PDF report")
            abort(500, description="Failed to generate PDF report")
        
        try:
            return send_file(
                output_path,
                as_attachment=True,
                download_name=f'webassure_report_{timestamp}.pdf',
                mimetype='application/pdf'
            )
        except Exception as e:
            print(f"Error sending PDF file: {e}")
            abort(500, description="Error sending PDF file")
            
    except Exception as e:
        print(f"Error in download_pdf route: {e}")
        abort(500, description=str(e))

def load_email_config():
    try:
        with open("email_config.json", "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading email config: {e}")
        return None

@app.route("/about")
def about():
    return render_template("landing.html", _anchor="about")

@app.route("/contact")
def contact():
    return render_template("contact.html")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3002, debug=False)
