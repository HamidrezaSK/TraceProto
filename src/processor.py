# processor.py

import os
import duckdb
import pandas as pd
import re
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import argparse
import psutil

# --- Event Structured Dataclass ---
@dataclass
class Event:
    pid: int
    timestamp_start: datetime
    command: str
    arguments: list
    source: str  # 'strace' or 'ebpf'

# --- Ingestion Helpers ---
def find_trace_files(session_dir):
    return [os.path.join(session_dir, f) for f in os.listdir(session_dir) if "-trace.txt" in f]

def read_trace_file(filepath):
    with open(filepath, "r") as f:
        return f.readlines()

# --- Parsing Functions ---

# Calculate boot time for eBPF timestamps
boot_time = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)

def parse_ebpf_line(line):
    try:
        parts = line.strip().split()
        if len(parts) < 4:
            return None

        nsecs = int(parts[0])
        pid = int(parts[1])

        command_index = parts.index("exec") + 1
        command = parts[command_index]
        arguments = parts[command_index+1:]
        arguments = [arg for arg in arguments if arg != "(null)"]

        timestamp = boot_time + timedelta(microseconds=nsecs/1000)

        return Event(
            pid=pid,
            timestamp_start=timestamp,
            command=command,
            arguments=arguments,
            source="ebpf"
        )

    except Exception as e:
        print(f"Failed to parse eBPF line: {line.strip()}. Error: {e}")
        return None

def parse_strace_line(line):
    try:
        # Example: 14:52:10.123456 execve("/usr/bin/python3", ["python3", "script.py"], 0x7ffc1234) = 0
        match = re.match(r'(\d+:\d+:\d+\.\d+)\s+execve\("([^"]+)", \[(.*?)\], .*?\)', line.strip())
        if not match:
            return None

        timestamp_str, command, args_str = match.groups()

        # Parse timestamp
        timestamp = datetime.strptime(timestamp_str, "%H:%M:%S.%f")
        today = datetime.now(timezone.utc).date()
        timestamp_start = datetime.combine(today, timestamp.time(), tzinfo=timezone.utc)

        # Parse arguments
        args = []
        if args_str:
            args = [arg.strip('"') for arg in args_str.split(', ') if arg.strip()]

        return Event(
            pid=None,  # We will assign PID later if available from filename
            timestamp_start=timestamp_start,
            command=command,
            arguments=args,
            source="strace"
        )

    except Exception as e:
        print(f"Failed to parse strace line: {line.strip()}. Error: {e}")
        return None

# --- Filtering Function ---
def filter_event(event):
    # For now, keep all events
    return True

# --- Storage Function ---
def store_events_to_duckdb(events, db_path):
    df = pd.DataFrame([e.__dict__ for e in events])
    con = duckdb.connect(database=db_path, read_only=False)
    con.execute("CREATE OR REPLACE TABLE events AS SELECT * FROM df")
    con.close()

# --- Main Processing Pipeline ---
def process_session(session_dir, mode):
    trace_files = find_trace_files(session_dir)
    all_events = []

    def process_file(file_path):
        local_events = []
        filename = os.path.basename(file_path)

        # Infer PID if strace mode and -ff used
        inferred_pid = None
        if mode == "strace" and '.' in filename:
            try:
                inferred_pid = int(filename.split('.')[-1])
            except ValueError:
                inferred_pid = None

        lines = read_trace_file(file_path)
        for line in lines:
            if mode == "strace":
                event = parse_strace_line(line)
                if event:
                    event.pid = inferred_pid  # Assign inferred PID
            else:  # ebpf
                event = parse_ebpf_line(line)

            if event and filter_event(event):
                local_events.append(event)

        return local_events

    # Optional: Parallel parsing
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(process_file, file) for file in trace_files]
        for f in futures:
            all_events.extend(f.result())

    # Save all events
    db_path = os.path.join(session_dir, "events.duckdb")
    store_events_to_duckdb(all_events, db_path)

    print(f"Processed {len(all_events)} events into {db_path}")

# --- CLI Entry Point ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process trace files into structured events")
    parser.add_argument("--session", required=True, help="Path to the session directory")
    parser.add_argument("--mode", choices=["strace", "ebpf"], required=True, help="Trace mode used during collection")
    args = parser.parse_args()

    process_session(args.session, args.mode)