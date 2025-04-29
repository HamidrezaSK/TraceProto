import subprocess
import os
import time
import argparse
import threading
import psutil
import csv
from datetime import datetime, timezone
import tempfile
# --- Imports ---

# --- Setup Paths ---
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.join(CURRENT_DIR, "../data")

PIPELINES = {
    "pipeline-1": os.path.join(CURRENT_DIR, "../pipelines/pipeline_1.sh"),
    "pipeline-2": os.path.join(CURRENT_DIR, "../pipelines/pipeline_2.sh")
}

NUM_RUNS = 1

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
def create_session_directory(mode):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    tag = mode + '_' + timestamp
    session_dir = os.path.join(BASE_DIR, tag)
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

    bpftrace_script = '''
        tracepoint:syscalls:sys_enter_execve
        {
            printf("%lld %d exec %s", nsecs, pid, str(args->filename));
            printf(" %s", str(args->argv[0]));
            printf(" %s", str(args->argv[1]));
            printf(" %s", str(args->argv[2]));
            printf("\\n");
        }
    '''

    # Use a temp file for bpftrace output
    with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
        tmp_path = tmp.name
        tmp.close()

    with open(tmp_path, "w", buffering=1) as tmp_out:
        bpftrace_proc = subprocess.Popen(
            ["sudo", "bpftrace", "-e", bpftrace_script],
            stdout=tmp_out,
            stderr=subprocess.DEVNULL,
            text=True
        )

        time.sleep(2)  # Give bpftrace time to attach

        pipeline_proc = subprocess.Popen(["bash", pipeline_path],
                                         stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
        pipeline_proc.wait()

        time.sleep(1)  # Let bpftrace flush final events
        bpftrace_proc.terminate()
        bpftrace_proc.wait()

    # Move bpftrace output to final trace file
    with open(tmp_path, "r") as f_in, open(trace_file, "w") as f_out:
        f_out.write(f_in.read())

    os.remove(tmp_path)

    stop_event.set()
    metrics_thread.join()

    print(f"Trace:   {trace_file}")
    print(f"Metrics: {metrics_file}")

# --- Main ---
def main():
    parser = argparse.ArgumentParser(description="Observability Agent Collector")
    parser.add_argument("--mode", choices=["strace", "ebpf"], required=True, help="Collection mode: strace or ebpf")
    parser.add_argument("--parallel", action="store_true", help="Enable parallel pipeline execution")
    args = parser.parse_args()

    session_dir = create_session_directory(args.mode)
    print(f"Session directory created at: {session_dir}")

    for run_id in range(1, NUM_RUNS + 1):
        if args.parallel and args.mode == "strace":
            # Parallel mode
            processes = []
            for pipeline_name, pipeline_path in PIPELINES.items():
                p = threading.Thread(target=run_pipeline_with_strace, args=(pipeline_name, pipeline_path, session_dir, run_id))
                p.start()
                processes.append(p)

            # Wait for all to finish
            for p in processes:
                p.join()

        else:
            # Serial mode (default)
            for pipeline_name, pipeline_path in PIPELINES.items():
                if args.mode == "strace":
                    run_pipeline_with_strace(pipeline_name, pipeline_path, session_dir, run_id)
                elif args.mode == "ebpf":
                    run_pipeline_with_ebpf(pipeline_name, pipeline_path, session_dir, run_id)

        time.sleep(1)

if __name__ == "__main__":
    main()
