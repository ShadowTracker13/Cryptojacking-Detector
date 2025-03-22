import psutil
import time
import socket

# List of known mining pool domains (for basic detection)
KNOWN_MINING_POOLS = [
    "pool.minexmr.com", "xmrpool.eu", "nanopool.org", 
    "supportxmr.com", "moneroocean.stream"
]

# Function to check CPU usage spikes
def check_cpu_usage(threshold=80, duration=5):
    """Detects high CPU usage for a specific duration."""
    print("Monitoring CPU Usage...")
    for _ in range(duration):
        cpu_usage = psutil.cpu_percent(interval=1)
        if cpu_usage > threshold:
            print(f"High CPU Usage Detected: {cpu_usage}%")
            return True
    return False

# Function to identify suspicious processes
def detect_suspicious_processes():
    """Finds processes using excessive CPU resources."""
    print("Scanning for High CPU Usage Processes...")
    suspicious_processes = []
    
    for process in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            if process.info['cpu_percent'] > 50:  # Adjust threshold as needed
                suspicious_processes.append(process.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    return suspicious_processes

# Function to check network connections for mining pool activity
def detect_mining_pools():
    """Checks active network connections against known mining pools."""
    print("Checking Network Connections for Mining Pools...")
    suspicious_connections = []
    
    for conn in psutil.net_connections(kind='inet'):
        try:
            if conn.status == psutil.CONN_ESTABLISHED:
                remote_ip = conn.raddr.ip
                remote_host = socket.gethostbyaddr(remote_ip)[0] if remote_ip else None
                
                if remote_host and any(pool in remote_host for pool in KNOWN_MINING_POOLS):
                    suspicious_connections.append((conn.pid, remote_host))
        except (socket.herror, socket.gaierror, psutil.NoSuchProcess, IndexError):
            continue

    return suspicious_connections

# Main function to run the cryptojacking detector
def main():
    print("\nStarting Cryptojacking Detector...\n")
    
    # Check CPU Usage
    if check_cpu_usage():
        print("Possible Cryptojacking Activity Detected Due to High CPU Usage!")

    # Scan for suspicious processes
    suspicious_procs = detect_suspicious_processes()
    if suspicious_procs:
        print("\nSuspicious High-CPU Processes Found:")
        for proc in suspicious_procs:
            print(f"PID: {proc['pid']}, Process: {proc['name']}, CPU Usage: {proc['cpu_percent']}%")
    else:
        print("\nNo High-CPU Usage Processes Detected.")

    # Check for mining pool connections
    mining_connections = detect_mining_pools()
    if mining_connections:
        print("\n Suspicious Connections to Mining Pools Found:")
        for pid, host in mining_connections:
            print(f" Process {pid} is connected to mining pool: {host}")
    else:
        print("\n No Suspicious Network Connections Found.")

    print("\n  Cryptojacking Detection Completed!\n")

if __name__ == "__main__":
    main()
