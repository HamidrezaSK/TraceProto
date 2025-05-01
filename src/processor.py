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
    duration_sec: float = None

# --- Ingestion Helpers ---
def find_trace_files(session_dir):
    return [os.path.join(session_dir, f) for f in os.listdir(session_dir) if "-trace.txt" in f]

def read_trace_file(filepath):
    with open(filepath, "r") as f:
        return f.readlines()

# --- Parsing Functions ---

# Calculate boot time for eBPF timestamps
boot_time = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)

def parse_enhanced_ebpf_trace(trace_file_path):
    start_map = {}
    end_map = {}
    events = []

    with open(trace_file_path, "r") as f:
        for line in f:
            parts = line.strip().split()
            if not parts:
                continue

            if parts[0] == "START" and len(parts) >= 4:
                pid = int(parts[1])
                nsecs = int(parts[2])
                command = parts[3]
                args = [arg for arg in parts[4:] if arg != "(null)"]
                start_map[pid] = {
                    "timestamp": boot_time + timedelta(microseconds=nsecs // 1000),
                    "command": command,
                    "args": args,
                    "raw_nsecs": nsecs
                }

            elif parts[0] == "END" and len(parts) >= 3:
                pid = int(parts[1])
                nsecs = int(parts[2])
                end_map[pid] = nsecs

    for pid in start_map:
        start_info = start_map[pid]
        end_nsecs = end_map.get(pid)
        duration_sec = None
        if end_nsecs:
            duration_sec = (end_nsecs - start_info["raw_nsecs"]) / 1e9

        event = Event(
            pid=pid,
            timestamp_start=start_info["timestamp"],
            command=start_info["command"],
            arguments=start_info["args"],
            source="ebpf",
            duration_sec=duration_sec
        )
        events.append(event)

    return events

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

def parse_strace_file(filepath):
    try:
        with open(filepath, "r") as f:
            lines = f.readlines()

        if not lines:
            return None

        filename = os.path.basename(filepath)
        pid = None
        if '.' in filename:
            try:
                pid = int(filename.split('.')[-1])
            except ValueError:
                pass

        # Find start (first execve) and end (last timestamp)
        execve_re = re.compile(r'^(\d+:\d+:\d+\.\d+)\s+execve\("([^"]+)", \[(.*?)\],')
        killed_re = re.compile(r'^(\d+:\d+:\d+\.\d+)\s+\+\+\+ killed by')

        start_time, end_time, command, arguments = None, None, None, []

        for line in lines:
            exec_match = execve_re.match(line)
            if exec_match and not start_time:
                ts_str, command, args_str = exec_match.groups()
                timestamp = datetime.strptime(ts_str, "%H:%M:%S.%f")
                today = datetime.now(timezone.utc).date()
                start_time = datetime.combine(today, timestamp.time(), tzinfo=timezone.utc)

                if args_str:
                    arguments = [arg.strip('"') for arg in args_str.split(', ') if arg]

            if 'killed by' in line or 'exited' in line:
                match = killed_re.match(line)
                if match:
                    ts_str = match.group(1)
                    timestamp = datetime.strptime(ts_str, "%H:%M:%S.%f")
                    today = datetime.now(timezone.utc).date()
                    end_time = datetime.combine(today, timestamp.time(), tzinfo=timezone.utc)

        if not start_time or not command:
            return None

        duration_sec = (end_time - start_time).total_seconds() if end_time else None

        return Event(
            pid=pid,
            timestamp_start=start_time,
            command=command,
            arguments=arguments,
            source="strace",
            duration_sec=duration_sec
        )

    except Exception as e:
        print(f"Failed to parse strace file {filepath}: {e}")
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
        if mode == "strace":
            event = parse_strace_file(file_path)
            return [event] if event else []
        else:
            # eBPF case
            if os.path.basename(file_path) == "ebpf-global-trace.txt":
                return parse_enhanced_ebpf_trace(file_path)

            # Otherwise fallback to original eBPF line-based parser
            events = []
            for line in read_trace_file(file_path):
                event = parse_ebpf_line(line)
                if event and filter_event(event):
                    events.append(event)
            return events

    # Parallel parsing
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