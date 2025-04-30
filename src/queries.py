import os
import glob
import duckdb
import pandas as pd

# --- Query 1: Execution Time Analysis (Strace) ---

def compute_avg_duration_per_command(db_path):
    con = duckdb.connect(database=db_path, read_only=True)

    df = con.execute("""
        SELECT pid, command, timestamp_start
        FROM events
        WHERE source = 'strace' AND pid IS NOT NULL
    """).fetchdf()

    con.close()

    if df.empty:
        print("No strace events found.")
        return pd.DataFrame()

    # Group by PID to calculate duration per process
    grouped = df.groupby('pid')
    durations = []

    for pid, group in grouped:
        start_time = group['timestamp_start'].min()
        end_time = group['timestamp_start'].max()
        duration_sec = (end_time - start_time).total_seconds()
        command = group.sort_values('timestamp_start').iloc[0]['command']
        durations.append({'command': command, 'duration_sec': duration_sec})

    durations_df = pd.DataFrame(durations)
    result = durations_df.groupby('command').agg(avg_duration_sec=('duration_sec', 'mean')).reset_index()

    print("\nAverage Execution Time per Command (seconds):")
    print(result.sort_values('avg_duration_sec', ascending=False))

    return result

# --- Query 2: Resource Consumption Ranking ---

def compute_cpu_hours_per_command(events_df, metrics_df, sample_interval_sec=0.1):
    if events_df.empty or metrics_df.empty:
        print("Missing event or metric data.")
        return pd.DataFrame()

    # Join metrics with events on PID
    merged = metrics_df.merge(events_df, on="pid", how="inner")

    # Estimate CPU seconds per row
    merged["cpu_seconds"] = merged["cpu_percent"] * sample_interval_sec / 100.0

    merged["command"] = merged["command_y"]  # use full path
    result = merged.groupby("command").agg(cpu_hours=("cpu_seconds", lambda x: sum(x)/3600)).reset_index()


    print("\nTop Commands by Estimated CPU Usage (hours):")
    print(result.sort_values("cpu_hours", ascending=False).head(3))

    return result

# --- Load all metrics and filter low CPU usage ---

def load_all_metrics_from_session(session_dir):
    metric_files = glob.glob(os.path.join(session_dir, "*-metrics.csv"))
    if not metric_files:
        print("No metrics files found in session directory.")
        return pd.DataFrame()

    frames = []
    for path in metric_files:
        try:
            df = pd.read_csv(path)
            df["pid"] = df["pid"].astype(int)
            df["cpu_percent"] = df["cpu_percent"].astype(float)
            df = df[df["cpu_percent"] >= 1.0]  # Filter out low CPU noise
            frames.append(df)
        except Exception as e:
            print(f"Failed to load {path}: {e}")

    if frames:
        return pd.concat(frames, ignore_index=True)
    else:
        return pd.DataFrame()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run Tracer analysis queries")
    parser.add_argument("--session", required=True, help="Path to session folder containing events.duckdb")
    args = parser.parse_args()

    events_db = os.path.join(args.session, "events.duckdb")
    metrics_df = load_all_metrics_from_session(args.session)

    con = duckdb.connect(events_db)
    events_df = con.execute("SELECT pid, command FROM events WHERE pid IS NOT NULL").fetchdf()
    con.close()

    compute_avg_duration_per_command(events_db)
    compute_cpu_hours_per_command(events_df, metrics_df)
