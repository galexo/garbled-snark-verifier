#!/usr/bin/env python3
"""
Benchmark script for groth16_safe_garble example.
Runs all combinations of instance modes, gate hashers, and ciphertext hashers.
Generates a markdown report with timing results.
"""

import subprocess
import re
import time
from datetime import datetime
from pathlib import Path
from itertools import product

# Configuration
INSTANCE_MODES = ["single", "cpu_count"]
GATE_HASHERS = ["blake3", "sha256", "swankyaes"]
CIPHERTEXT_HASHERS = ["aes", "blake3", "sha256", "swankyaes"]
LOG_DIR = Path("benchmark_logs")
REPORT_FILE = Path("benchmark_report.md")

# Regex pattern to extract timing from logs
TIMING_PATTERN = re.compile(r"garbling: in ([\d.]+)s")


def get_cpu_count():
    """Get the number of physical CPUs."""
    try:
        import multiprocessing
        # Try to get physical cores (psutil would be better but may not be available)
        return multiprocessing.cpu_count()
    except:
        return "unknown"


def run_benchmark(instances, gate_hasher, ct_hasher, log_file):
    """
    Run a single benchmark combination and save output to log file.

    Returns: (success: bool, duration: float or None, error: str or None)
    """
    cmd = [
        "cargo", "run", "--example", "groth16_safe_garble", "--release", "--",
        "--instances", instances,
        "--gate-hasher", gate_hasher,
        "--ciphertext-hasher", ct_hasher
    ]

    env = {"RUST_LOG": "info"}

    print(f"  Running: --instances {instances} --gate-hasher {gate_hasher} --ciphertext-hasher {ct_hasher}")
    print(f"  Log file: {log_file}")

    start_time = time.time()
    try:
        with open(log_file, 'w') as f:
            result = subprocess.run(
                cmd,
                env={**subprocess.os.environ.copy(), **env},
                stdout=f,
                stderr=subprocess.STDOUT,
                timeout=3600  # 1 hour timeout
            )

        elapsed = time.time() - start_time

        if result.returncode != 0:
            return False, None, f"Non-zero exit code: {result.returncode}"

        return True, elapsed, None

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start_time
        return False, None, f"Timeout after {elapsed:.1f}s"
    except Exception as e:
        elapsed = time.time() - start_time
        return False, None, f"Error: {str(e)}"


def parse_timing(log_file):
    """
    Parse the garbling time from a log file.

    Returns: float (seconds) or None if not found
    """
    try:
        with open(log_file, 'r') as f:
            content = f.read()

        match = TIMING_PATTERN.search(content)
        if match:
            return float(match.group(1))

        return None
    except Exception as e:
        print(f"  Warning: Could not parse {log_file}: {e}")
        return None


def format_duration(seconds):
    """Format duration in human-readable form."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"


def generate_report(results, total_time):
    """
    Generate markdown report from benchmark results.

    results: list of (instances, gate_hasher, ct_hasher, time_s, status)
    """
    cpu_count = get_cpu_count()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(REPORT_FILE, 'w') as f:
        f.write("# Garbled Circuit Benchmark Results\n\n")
        f.write(f"**Generated:** {timestamp}\n\n")
        f.write(f"**System:** {cpu_count} physical CPUs\n\n")
        f.write(f"**Total benchmark time:** {format_duration(total_time)}\n\n")
        f.write("---\n\n")

        f.write("## Results\n\n")
        f.write("| Instance Mode | Gate Hasher | Ciphertext Hasher | Time (s) | Status |\n")
        f.write("|--------------|-------------|-------------------|----------|--------|\n")

        for instances, gate_hasher, ct_hasher, time_s, status in results:
            time_str = f"{time_s:.3f}" if time_s is not None else "N/A"
            f.write(f"| {instances} | {gate_hasher} | {ct_hasher} | {time_str} | {status} |\n")

        f.write("\n---\n\n")

        # Summary statistics
        successful = [r for r in results if r[3] is not None]
        if successful:
            f.write("## Summary\n\n")
            f.write(f"**Successful runs:** {len(successful)}/{len(results)}\n\n")

            times = [r[3] for r in successful]
            f.write(f"**Fastest:** {min(times):.3f}s\n\n")
            f.write(f"**Slowest:** {max(times):.3f}s\n\n")
            f.write(f"**Average:** {sum(times)/len(times):.3f}s\n\n")

            # Group by instance mode
            single_times = [r[3] for r in successful if r[0] == "single"]
            multi_times = [r[3] for r in successful if r[0] == "cpu_count"]

            if single_times:
                f.write(f"**Single instance average:** {sum(single_times)/len(single_times):.3f}s\n\n")
            if multi_times:
                f.write(f"**CPU count instance average:** {sum(multi_times)/len(multi_times):.3f}s\n\n")

    print(f"\n✓ Report saved to: {REPORT_FILE}")


def main():
    """Main benchmark orchestration."""
    print("=" * 70)
    print("Garbled Circuit Benchmark Suite")
    print("=" * 70)
    print()

    # Create log directory
    LOG_DIR.mkdir(exist_ok=True)
    print(f"✓ Log directory: {LOG_DIR}/")
    print()

    # Generate all combinations
    combinations = list(product(INSTANCE_MODES, GATE_HASHERS, CIPHERTEXT_HASHERS))
    total_combinations = len(combinations)

    print(f"Total combinations to test: {total_combinations}")
    print(f"  Instance modes: {', '.join(INSTANCE_MODES)}")
    print(f"  Gate hashers: {', '.join(GATE_HASHERS)}")
    print(f"  Ciphertext hashers: {', '.join(CIPHERTEXT_HASHERS)}")
    print()
    print("=" * 70)
    print()

    results = []
    start_time = time.time()

    for idx, (instances, gate_hasher, ct_hasher) in enumerate(combinations, 1):
        print(f"[{idx}/{total_combinations}]")

        # Generate log filename
        log_file = LOG_DIR / f"{instances}_{gate_hasher}_{ct_hasher}.log"

        # Run benchmark
        success, wall_time, error = run_benchmark(instances, gate_hasher, ct_hasher, log_file)

        if success:
            # Parse timing from log
            garbling_time = parse_timing(log_file)
            if garbling_time is not None:
                print(f"  ✓ Completed in {format_duration(wall_time)} (garbling: {garbling_time:.3f}s)")
                results.append((instances, gate_hasher, ct_hasher, garbling_time, "✓"))
            else:
                print(f"  ⚠ Completed but could not parse timing")
                results.append((instances, gate_hasher, ct_hasher, None, "⚠ No timing"))
        else:
            print(f"  ✗ Failed: {error}")
            results.append((instances, gate_hasher, ct_hasher, None, f"✗ {error}"))

        # Progress estimate
        elapsed = time.time() - start_time
        if idx > 0:
            avg_time_per_run = elapsed / idx
            remaining = (total_combinations - idx) * avg_time_per_run
            print(f"  Estimated time remaining: {format_duration(remaining)}")

        print()

    # Generate report
    total_time = time.time() - start_time
    print("=" * 70)
    print(f"Benchmark complete! Total time: {format_duration(total_time)}")
    print("=" * 70)
    print()

    generate_report(results, total_time)
    print()
    print("Done!")


if __name__ == "__main__":
    main()
