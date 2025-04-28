import os
import json
import traceback
import threading
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

            # Initialize scanner and run scan
            scanner = ThreadedScanner()
            file_paths = {
                'nikto_output': os.path.join("output", f"nikto_{int(time.time())}.json"),
                'zap_output': os.path.join("output", f"zap_{int(time.time())}.json"),
                'combined_output': os.path.join("output", f"combined_{int(time.time())}.json")
            }
            
            results = scanner.run_concurrent_scan(
                target_url, 
                file_paths,
                nikto_tuning=request.form.get("nikto_tuning", ""),
                zap_options=[opt for opt in request.form.getlist("zap_options") if opt]
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

            scan_id = saved_results.get('scan_id')
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
        print(f"[*] Starting PDF generation for report ID: {report_id}")
        pdf_type = request.args.get('type', 'complete')
        
        # Get report data
        db_handler = DatabaseHandler()
        report = db_handler.get_report_by_id(report_id)
        
        if not report:
            print(f"[-] Report not found for ID: {report_id}")
            return jsonify({"error": "Report not found"}), 404

        # Prepare scan results for PDF generation
        scan_results = {
            'timestamp': report['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
            'target_url': report['target_url'],
            'metrics': report.get('metrics', {}),
            'summary': report.get('summary', {}),
            'nikto_results': report.get('nikto_results', {}),
            'zap_results': report.get('zap_results', {})
        }

        # Create PDF file name and path
        pdf_filename = f"webassure_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        temp_dir = tempfile.mkdtemp()  # Create a unique temp directory
        pdf_path = os.path.join(temp_dir, pdf_filename)

        print(f"[*] Generating PDF: {pdf_path}")
        success = generate_pdf_report(scan_results, pdf_path, pdf_type)

        if success and os.path.exists(pdf_path):
            print("[+] PDF generated successfully")
            try:
                response = send_file(
                    pdf_path,
                    mimetype='application/pdf',
                    as_attachment=True,
                    download_name=pdf_filename
                )
                return response
            except Exception as e:
                print(f"[-] Error sending file: {e}")
                return jsonify({"error": "Failed to send PDF"}), 500
            finally:
                # Clean up temp directory in a separate thread
                def cleanup():
                    time.sleep(1)
                    try:
                        import shutil
                        shutil.rmtree(temp_dir)
                    except Exception as e:
                        print(f"[-] Cleanup error: {e}")
                
                threading.Thread(target=cleanup).start()
        else:
            print("[-] PDF generation failed")
            return jsonify({"error": "Failed to generate PDF"}), 500

    except Exception as e:
        print(f"[-] Error in download_pdf: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

def load_email_config():
    try:
        with open("email_config.json", "r") as config_file:
            return json.load(config_file)
    except Exception as e:
        print(f"Error loading email configuration: {e}")
        return None

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3002, debug=False)
