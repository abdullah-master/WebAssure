import threading
from queue import Queue
from scan import run_nikto, run_owasp_zap

class ThreadedScanner:
    def __init__(self):
        self.results = {}
        self.threads = []
        self.results_queue = Queue()

    def nikto_thread(self, target_url, output_file, tuning=""):
        results = run_nikto(target_url, output_file, tuning)
        self.results_queue.put(('nikto', results))

    def zap_thread(self, target_url, output_file, options=None):
        # Ensure the updated API key is used in the ZAP scan
        results = run_owasp_zap(target_url, output_file, options)
        self.results_queue.put(('zap', results))

    def run_concurrent_scan(self, target_url, file_paths, nikto_tuning="", zap_options=None):
        # Start Nikto scan thread
        nikto_thread = threading.Thread(
            target=self.nikto_thread,
            args=(target_url, file_paths['nikto_output'], nikto_tuning)
        )
        
        # Start ZAP scan thread
        zap_thread = threading.Thread(
            target=self.zap_thread,
            args=(target_url, file_paths['zap_output'], zap_options)
        )

        # Start both threads
        nikto_thread.start()
        zap_thread.start()

        # Wait for both threads to complete
        nikto_thread.join()
        zap_thread.join()

        # Collect results from queue
        while not self.results_queue.empty():
            scanner_type, result = self.results_queue.get()
            self.results[scanner_type] = result

        return self.results
