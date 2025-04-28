# src/collector.py
import subprocess
import os
import time
from datetime import datetime

PIPELINE_DIR = "../pipelines"
OUTPUT_DIR = "../data"

os.makedirs(OUTPUT_DIR, exist_ok=True)

PIPELINES = ["pipeline_1.sh", "pipeline_2.sh"]
NUM_RUNS = 10  # Number of times to run each pipeline

def run_pipeline_with_tracing(pipeline_name, run_id):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    trace_output_file = os.path.join(OUTPUT_DIR, f"{pipeline_name}_run{run_id}_{timestamp}_trace.txt")

    pipeline_path = os.path.join(PIPELINE_DIR, pipeline_name)
    cmd = [
        "strace",
        "-f",  # Follow child processes
        "-tt", # Include timestamps
        "-e", "trace=execve",  # Only execve system calls
        "-o", trace_output_file,  # Output file
        "bash", pipeline_path
    ]

    print(f"Running {pipeline_name} (Run {run_id}) with tracing...")
    subprocess.run(cmd, check=False)
    print(f"Completed {pipeline_name} (Run {run_id}). Trace saved to {trace_output_file}")

def main():
    for pipeline in PIPELINES:
        for run_id in range(1, NUM_RUNS + 1):
            run_pipeline_with_tracing(pipeline, run_id)
            time.sleep(1)  # Small pause between runs

if __name__ == "__main__":
    main()
