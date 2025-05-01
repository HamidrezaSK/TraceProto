# --- Imports ---
import subprocess
import os
import time
import argparse
import threading
import csv
from datetime import datetime, timezone
import tempfile

# --- Constants ---
# eBPF script to trace execve system calls
ENHANCED_BPFTRACE_SCRIPT = '''
BEGIN {
    printf("TRACE_START\\n");
}

tracepoint:syscalls:sys_enter_execve
{
    @start[pid] = nsecs;
    printf("START %d %lld %s %s %s %s\\n",
        pid,
        nsecs,
        str(args->filename),
        str(args->argv[0]),
        str(args->argv[1]),
        str(args->argv[2]));
}

tracepoint:sched:sched_process_exit
/@start[pid]/
{
    printf("END %d %lld\\n", pid, nsecs);
    delete(@start[pid]);
}
'''

ANOMALY_BPFTRACE_SCRIPT = '''
tracepoint:syscalls:sys_exit_execve
/args->ret < 0/
{
    printf("FAILED execve pid=%d ret=%d\n", pid, args->ret);
}
'''

NUM_RUNS = 10

# --- Setup Paths ---
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.join(CURRENT_DIR, "../data")

PIPELINES = {
    "pipeline-1": os.path.join(CURRENT_DIR, "../pipelines/pipeline_1.sh"),
    "pipeline-2": os.path.join(CURRENT_DIR, "../pipelines/pipeline_2.sh")
}

# --- System Top Collector Thread ---
def collect_system_top(output_file, stop_event, interval_sec=0.1):
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp_utc", "pid", "cpu_percent", "mem_percent", "command"])

        while not stop_event.is_set():
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f %Z")

            try:
                result = subprocess.run(
                    ["top", "-b", "-n", "1"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True
                )

                lines = result.stdout.splitlines()
                header_found = False
                for line in lines:
                    if line.strip().startswith("PID"):
                        header_found = True
                        continue
                    if header_found and line.strip():
                        cols = line.split()
                        if len(cols) >= 12:
                            pid = cols[0]
                            cpu = cols[8]
                            mem = cols[9]
                            cmd = cols[11]
                            writer.writerow([timestamp, pid, cpu, mem, cmd])
            except Exception as e:
                print(f"Error collecting top: {e}")

            time.sleep(interval_sec)

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
    metrics_thread = threading.Thread(
        target=collect_system_top,
        args=(metrics_file, stop_event)
    )
    metrics_thread.start()

    cmd = [
        "strace", "-ff", "-tt",
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
    metrics_thread = threading.Thread(
        target=collect_system_top,
        args=(metrics_file, stop_event)
    )
    metrics_thread.start()

    # Deprecated: Original bpftrace script
    # bpftrace_script = '''
    #     tracepoint:syscalls:sys_enter_execve
    #     {
    #         printf("%lld %d exec %s", nsecs, pid, str(args->filename));
    #         printf(" %s", str(args->argv[0]));
    #         printf(" %s", str(args->argv[1]));
    #         printf(" %s", str(args->argv[2]));
    #         printf("\\n");
    #     }
    # '''

    # Use a temp file for bpftrace output
    with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
        tmp_path = tmp.name
        tmp.close()

    # Write bpftrace script to temp file
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write(ENHANCED_BPFTRACE_SCRIPT)
        script_path = f.name

    with open(trace_file, "w", buffering=1) as trace_out:
        bpftrace_proc = subprocess.Popen(
            ["sudo", "bpftrace", script_path],
            stdout=trace_out,
            stderr=subprocess.DEVNULL,
            text=True
        )

    # with open(tmp_path, "w", buffering=1) as tmp_out:
    #     bpftrace_proc = subprocess.Popen(
    #         ["sudo", "bpftrace", "-e", bpftrace_script],
    #         stdout=tmp_out,
    #         stderr=subprocess.DEVNULL,
    #         text=True
    #     )

        time.sleep(1)  # Give bpftrace time to attach

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
    os.remove(script_path)

    stop_event.set()
    metrics_thread.join()

    print(f"Trace:   {trace_file}")
    print(f"Metrics: {metrics_file}")

# --- Enhanced BPFTrace Script ---
def run_all_pipelines_with_ebpf(session_dir):
    trace_file = os.path.join(session_dir, "ebpf-global-trace.txt")
    metrics_file = os.path.join(session_dir, "ebpf-global-metrics.csv")

    print(f"Running all pipelines in parallel with global eBPF...")

    stop_event = threading.Event()
    metrics_thread = threading.Thread(
        target=collect_system_top,
        args=(metrics_file, stop_event)
    )
    metrics_thread.start()

    # Write bpftrace script to temp file
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write(ENHANCED_BPFTRACE_SCRIPT)
        script_path = f.name

    with open(trace_file, "w", buffering=1) as trace_out:
        bpftrace_proc = subprocess.Popen(
            ["sudo", "bpftrace", script_path],
            stdout=trace_out,
            stderr=subprocess.DEVNULL,
            text=True
        )
        anomaly_proc, anomaly_script_path = start_anomaly_monitor(session_dir)
        time.sleep(1)  # Give bpftrace time to attach

        # Run all pipelines in parallel
        procs = []
        for pipeline_path in PIPELINES.values():
            p = subprocess.Popen(["bash", pipeline_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs.append(p)

        for p in procs:
            p.wait()

        stop_event.set()
        metrics_thread.join()

        time.sleep(1)  # Let bpftrace flush final events
        bpftrace_proc.terminate()
        bpftrace_proc.wait()

        anomaly_proc.terminate()
        anomaly_proc.wait()
        os.remove(anomaly_script_path)
        print(f"Anomaly log written to: {os.path.join(session_dir, 'anomaly-log.txt')}")

    os.remove(script_path)

    print(f"Trace:   {trace_file}")
    print(f"Metrics: {metrics_file}")

def start_anomaly_monitor(session_dir):
    log_file = os.path.join(session_dir, "anomaly-log.txt")

    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write(ANOMALY_BPFTRACE_SCRIPT)
        script_path = f.name

    anomaly_proc = subprocess.Popen(
        ["sudo", "bpftrace", script_path],
        stdout=open(log_file, "w"),
        stderr=subprocess.DEVNULL,
        text=True
    )

    return anomaly_proc, script_path

# --- Main ---
def main():
    parser = argparse.ArgumentParser(description="Observability Agent Collector")
    parser.add_argument("--mode", choices=["strace", "ebpf"], required=True, help="Collection mode: strace or ebpf")
    parser.add_argument("--parallel", action="store_true", help="Enable parallel pipeline execution")
    args = parser.parse_args()

    session_dir = create_session_directory(args.mode)
    print(f"Session directory created at: {session_dir}")

    for run_id in range(1, NUM_RUNS + 1):
        if args.parallel:
            # Parallel mode
            if args.mode == "strace":
                processes = []
                for pipeline_name, pipeline_path in PIPELINES.items():
                    p = threading.Thread(target=run_pipeline_with_strace, args=(pipeline_name, pipeline_path, session_dir, run_id))
                    p.start()
                    processes.append(p)
                # Wait for all to finish
                for p in processes:
                    p.join()
            elif args.mode == "ebpf":
                run_all_pipelines_with_ebpf(session_dir)
        else:
            # Serial mode (default)
            for pipeline_name, pipeline_path in PIPELINES.items():
                if args.mode == "strace":
                    run_pipeline_with_strace(pipeline_name, pipeline_path, session_dir, run_id)
                elif args.mode == "ebpf":
                    run_pipeline_with_ebpf(pipeline_name, pipeline_path, session_dir, run_id)

        time.sleep(1)
    print(f"SESSION_PATH::{session_dir}")

if __name__ == "__main__":
    main()
