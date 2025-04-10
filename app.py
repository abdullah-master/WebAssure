import os
import json
import traceback
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_from_directory, abort, send_file
from scan import run_nikto, run_owasp_zap, save_results
from email_script import send_email
from db_operations import DatabaseHandler
from pdf_generator import generate_pdf_report
import tempfile
import time
from threaded_scanner import ThreadedScanner

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

@app.route("/", methods=["GET"])
def landing():
    try:
        db_handler = DatabaseHandler()
        scan_history = db_handler.get_scan_history()
        
        if not scan_history:
            return render_template("landing.html", reports=[], error=None)
        
        reports = []
        for scan in scan_history:
            try:
                reports.append({
                    'timestamp': scan['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                    'target_url': scan['target_url'],
                    'metrics': scan.get('metrics', {}),
                    'summary': scan.get('summary', {}),
                    'files': scan.get('scan_files', {}),
                    'id': str(scan['_id'])
                })
            except Exception as e:
                print(f"[-] Error formatting scan result: {e}")
                continue
        
        return render_template("landing.html", reports=reports)
    except Exception as e:
        print(f"[-] Error loading landing page: {e}")
        return render_template("landing.html", reports=[], error="Failed to load scan history")

@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "POST":
        try:
            target_url = request.form.get("target_url").strip()
            if not target_url.startswith(("http://", "https://")):
                target_url = f"http://{target_url}"

            send_email_option = request.form.get("send_email") == "on"
            nikto_tuning = request.form.get("nikto_tuning", "")
            zap_options = [
                request.form.get("zap_scanning"),
                request.form.get("zap_alert"),
                request.form.get("zap_depth"),
                request.form.get("zap_duration"),
            ]
            zap_options = [opt for opt in zap_options if opt]

            scan_time = datetime.now().strftime("%Y%m%d_%H%M%S")
            scan_dir = os.path.join(os.getcwd(), "output", scan_time)
            os.makedirs(scan_dir, exist_ok=True)

            file_paths = {
                'nikto_output': os.path.join(scan_dir, f"nikto_{scan_time}.json"),
                'zap_output': os.path.join(scan_dir, f"zap_{scan_time}.json"),
                'combined_output': os.path.join(scan_dir, f"combined_{scan_time}.json")
            }

            # Initialize and run threaded scanner
            scanner = ThreadedScanner()
            # Ensure the updated API key is used
            results = scanner.run_concurrent_scan(
                target_url, 
                file_paths,
                nikto_tuning=nikto_tuning,
                zap_options=zap_options
            )

            # Save results
            saved_results = save_results(
                target_url,
                results.get('nikto', {}),
                results.get('zap', {}),
                file_paths
            )

            if not saved_results:
                return "Error saving scan results", 500

            if send_email_option:
                email_config = load_email_config()
                if email_config:
                    send_email(email_config, file_paths['combined_output'])

            scan_id = saved_results.get('scan_id')
            if scan_id:
                return redirect(url_for("view_report", report_id=scan_id))
            return redirect(url_for("result"))

        except Exception as e:
            print(f"[-] Scan error: {e}")
            return f"Error during scan: {str(e)}", 500

    return render_template("main.html")

@app.route("/api/report/<report_id>")
def get_report_data(report_id):
    try:
        db_handler = DatabaseHandler()
        report = db_handler.get_report_by_id(report_id)
        
        if not report:
            return jsonify({"error": "Report not found"}), 404

        # Convert MongoDB ObjectId to string
        report['_id'] = str(report['_id'])
        
        # Format datetime for JSON
        if 'timestamp' in report:
            report['timestamp'] = report['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            
        return jsonify(report)
    except Exception as e:
        print(f"[-] Error retrieving report data: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/report/<report_id>")
def view_report(report_id):
    try:
        db_handler = DatabaseHandler()
        report = db_handler.get_report_by_id(report_id)
        
        if not report:
            return render_template("error.html", message="Report not found"), 404
            
        return render_template("result.html", report_id=report_id)
    except Exception as e:
        print(f"[-] Error loading report page: {e}")
        return render_template("error.html", message="Failed to load report"), 500

@app.route("/results")
def result():
    try:
        with open("output.json", "r") as output_file:
            results = json.load(output_file)
        return render_template("result.html", results=results)
    except FileNotFoundError:
        return "Error: No results found. Please perform a scan first."

@app.route('/get-output')
def get_output():
    directory = os.path.dirname(os.path.abspath(__file__))
    return send_from_directory(directory, 'output.json')

@app.route("/download-pdf/<report_id>")
def download_pdf(report_id):
    try:
        print(f"Attempting to download PDF for report ID: {report_id}")
        pdf_type = request.args.get('type', 'complete')
        
        db_handler = DatabaseHandler()
        report = db_handler.get_report_by_id(report_id)
        
        if not report:
            print(f"Report not found for ID: {report_id}")
            return "Report not found", 404

        # Load results from output files
        output_dir = report.get('scan_files', {}).get('output_dir')
        if not output_dir or not os.path.exists(output_dir):
            return "Scan output files not found", 404

        try:
            # Load combined results
            combined_file = os.path.join(output_dir, os.listdir(output_dir)[0])  # Get first file
            with open(combined_file, 'r') as f:
                scan_results = json.load(f)
                
            # Merge MongoDB metadata with scan results
            scan_results.update({
                'timestamp': report['timestamp'],
                'target_url': report['target_url'],
                'metrics': report['metrics'],
                'summary': report['summary']
            })

            # Create temporary file for PDF
            pdf_filename = f"zapnik_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            temp_dir = tempfile.gettempdir()
            pdf_path = os.path.join(temp_dir, pdf_filename)

            print(f"Generating PDF with type: {pdf_type}")
            if generate_pdf_report(scan_results, pdf_path, pdf_type):
                response = send_file(
                    pdf_path,
                    mimetype='application/pdf',
                    as_attachment=True,
                    download_name=pdf_filename
                )
                
                # Clean up in a separate thread to avoid file in use error
                def cleanup():
                    time.sleep(1)  # Wait for file to be sent
                    try:
                        if os.path.exists(pdf_path):
                            os.unlink(pdf_path)
                    except Exception as e:
                        print(f"[-] Error cleaning up PDF file: {e}")
                
                import threading
                threading.Thread(target=cleanup).start()
                
                return response
            else:
                return "Failed to generate PDF report", 500

        except Exception as e:
            print(f"[-] Error reading scan results: {e}")
            return "Error reading scan results", 500

    except Exception as e:
        print(f"[-] Error in download_pdf: {e}")
        print(traceback.format_exc())
        return "Error generating report", 500

def load_email_config():
    try:
        with open("email_config.json", "r") as config_file:
            return json.load(config_file)
    except Exception as e:
        print(f"Error loading email configuration: {e}")
        return None

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3002, debug=False)
