import threading
from queue import Queue
from scan import run_nikto, run_owasp_zap

class ThreadedScanner:
    def __init__(self):
        self.results = {}
        self.threads = []
        self.results_queue = Queue()

    def nikto_thread(self, target_url, output_file, tuning=""):
        try:
            results = run_nikto(target_url, output_file, tuning)
            self.results_queue.put(('nikto', results))
        except Exception as e:
            print(f"[-] Error in Nikto scan: {e}")
            self.results_queue.put(('nikto', {
                "scan_status": "error",
                "host": target_url,
                "error": str(e)
            }))

    def zap_thread(self, target_url, output_file, options=None):
        try:
            # Only run if ZAP is enabled in options
            if options and options.get('enabled', False):
                results = run_owasp_zap(target_url, output_file, options)
                self.results_queue.put(('zap', results))
            else:
                self.results_queue.put(('zap', {
                    "scan_status": "skipped",
                    "host": target_url,
                    "message": "ZAP scan was not selected"
                }))
        except Exception as e:
            print(f"[-] Error in ZAP scan: {e}")
            self.results_queue.put(('zap', {
                "scan_status": "error",
                "host": target_url,
                "error": str(e)
            }))

    def run_concurrent_scan(self, target_url, file_paths, nikto_tuning="", zap_options=None):
        """
        Run concurrent scans with Nikto and ZAP
        :param target_url: URL to scan
        :param file_paths: Dictionary containing output file paths
        :param nikto_tuning: Nikto tuning options string (e.g. "-Tuning 1")
        :param zap_options: Dictionary containing ZAP scan options
        """
        # Start Nikto scan thread if tuning is provided
        if nikto_tuning:
            nikto_thread = threading.Thread(
                target=self.nikto_thread,
                args=(target_url, file_paths['nikto_output'], nikto_tuning)
            )
            self.threads.append(nikto_thread)
            nikto_thread.start()

        # Start ZAP scan thread if enabled
        if zap_options and zap_options.get('enabled', False):
            zap_thread = threading.Thread(
                target=self.zap_thread,
                args=(target_url, file_paths['zap_output'], zap_options)
            )
            self.threads.append(zap_thread)
            zap_thread.start()

        # Wait for all threads to complete
        for thread in self.threads:
            thread.join()

        # Collect results from queue
        self.results = {}
        while not self.results_queue.empty():
            scanner_type, result = self.results_queue.get()
            self.results[scanner_type] = result

        return self.results
