import subprocess
import os
import time
import argparse
from datetime import datetime

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

PIPELINES = {
    "pipeline-1": os.path.join(CURRENT_DIR, "../pipelines/pipeline_1.sh"),
    "pipeline-2": os.path.join(CURRENT_DIR, "../pipelines/pipeline_2.sh")
}

BASE_DIR = os.path.join(CURRENT_DIR, "../data")


# Number of runs per pipeline
NUM_RUNS = 1

def create_session_directory():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    session_dir = os.path.join(BASE_DIR, timestamp)
    os.makedirs(session_dir, exist_ok=True)
    return session_dir

def run_pipeline_with_strace(pipeline_name, pipeline_path, session_dir, run_id):
    output_file = os.path.join(session_dir, f"{pipeline_name}-run{run_id:02d}.txt")
    cmd = [
        "strace",
        "-f",   # follow child processes
        "-tt",  # absolute timestamps
        "-e", "trace=execve",
        "-o", output_file,
        "bash", pipeline_path
    ]
    print(f"Running {pipeline_name} (Run {run_id}) with strace...")
    subprocess.run(cmd, check=False)
    print(f"Completed {pipeline_name} (Run {run_id}). Trace saved to {output_file}")

def run_pipeline_with_ebpf(pipeline_name, pipeline_path, session_dir, run_id):
    output_file = os.path.join(session_dir, f"{pipeline_name}-run{run_id:02d}.txt")

    bpftrace_script = 'tracepoint:syscalls:sys_enter_execve { printf("%d %s\\n", pid, str(args->filename)); }'

    print(f"Running {pipeline_name} (Run {run_id}) with eBPF...")

    # Start bpftrace
    bpftrace_proc = subprocess.Popen(
        ["sudo", "bpftrace", "-e", bpftrace_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    time.sleep(1)  # Give bpftrace time to attach

    # Start the pipeline
    pipeline_proc = subprocess.Popen(["bash", pipeline_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Wait for pipeline to finish
    pipeline_proc.wait()

    time.sleep(1)

    # Kill bpftrace
    bpftrace_proc.terminate()
    stdout, stderr = bpftrace_proc.communicate()

    with open(output_file, "w") as f:
        f.write(stdout)

    print(f"Completed {pipeline_name} (Run {run_id}). Trace saved to {output_file}")

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
            time.sleep(1)  # Small pause between runs

if __name__ == "__main__":
    main()
