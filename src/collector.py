import subprocess
import os
import time
import argparse
import threading
import psutil
from datetime import timezone
import csv
from datetime import datetime

# --- Setup Paths ---
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.join(CURRENT_DIR, "../data")

PIPELINES = {
    "pipeline-1": os.path.join(CURRENT_DIR, "../pipelines/pipeline_1.sh"),
    "pipeline-2": os.path.join(CURRENT_DIR, "../pipelines/pipeline_2.sh")
}

NUM_RUNS = 10

# --- Metrics Collector Thread ---
def collect_metrics(stop_event, output_file):
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "cpu_percent", "mem_used_mb"])

        while not stop_event.is_set():
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory().used / (1024 * 1024)
            writer.writerow([timestamp, cpu, round(mem, 2)])

# --- Session Directory ---
def create_session_directory():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    session_dir = os.path.join(BASE_DIR, timestamp)
    os.makedirs(session_dir, exist_ok=True)
    return session_dir

# --- Strace Pipeline ---
def run_pipeline_with_strace(pipeline_name, pipeline_path, session_dir, run_id):
    trace_file = os.path.join(session_dir, f"{pipeline_name}-run{run_id:02d}-trace.txt")
    metrics_file = os.path.join(session_dir, f"{pipeline_name}-run{run_id:02d}-metrics.csv")

    print(f"Running {pipeline_name} (Run {run_id}) with strace...")

    stop_event = threading.Event()
    metrics_thread = threading.Thread(target=collect_metrics, args=(stop_event, metrics_file))
    metrics_thread.start()

    cmd = [
        "strace", "-f", "-tt",
        "-e", "trace=execve",
        "-o", trace_file,
        "bash", pipeline_path
    ]
    subprocess.run(cmd, check=False)

    stop_event.set()
    metrics_thread.join()

    print(f"Trace: {trace_file}")
    print(f"Metrics: {metrics_file}")

# --- eBPF Pipeline ---
def run_pipeline_with_ebpf(pipeline_name, pipeline_path, session_dir, run_id):
    trace_file = os.path.join(session_dir, f"{pipeline_name}-run{run_id:02d}-trace.txt")
    metrics_file = os.path.join(session_dir, f"{pipeline_name}-run{run_id:02d}-metrics.csv")

    print(f"Running {pipeline_name} (Run {run_id}) with eBPF...")

    stop_event = threading.Event()
    metrics_thread = threading.Thread(target=collect_metrics, args=(stop_event, metrics_file))
    metrics_thread.start()

    bpftrace_script = 'tracepoint:syscalls:sys_enter_execve { printf("%d %s\\n", pid, str(args->filename)); }'
    bpftrace_proc = subprocess.Popen(
        ["sudo", "bpftrace", "-e", bpftrace_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    time.sleep(1)  # Give bpftrace time to attach

    pipeline_proc = subprocess.Popen(["bash", pipeline_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pipeline_proc.wait()

    time.sleep(1)
    bpftrace_proc.terminate()
    stdout, stderr = bpftrace_proc.communicate()

    with open(trace_file, "w") as f:
        f.write(stdout)

    stop_event.set()
    metrics_thread.join()

    print(f"Trace: {trace_file}")
    print(f"Metrics: {metrics_file}")

# --- Main ---
def main():
    parser = argparse.ArgumentParser(description="Observability Agent Collector")
    parser.add_argument("--mode", choices=["strace", "ebpf"], required=True, help="Collection mode: strace or ebpf")
    args = parser.parse_args()

    session_dir = create_session_directory()
    print(f"Session directory created at: {session_dir}")

    for pipeline_name, pipeline_path in PIPELINES.items():
        for run_id in range(1, NUM_RUNS + 1):
            if args.mode == "strace":
                run_pipeline_with_strace(pipeline_name, pipeline_path, session_dir, run_id)
            elif args.mode == "ebpf":
                run_pipeline_with_ebpf(pipeline_name, pipeline_path, session_dir, run_id)
            time.sleep(1)

if __name__ == "__main__":
    main()
