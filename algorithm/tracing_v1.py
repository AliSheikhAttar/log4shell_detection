import subprocess
import os
import sys
import time
import os
import glob


RED = "\033[31m"
RESET = "\033[0m"

tls_key_cmd = "export SSLKEYLOGFILE=$HOME/sslkeys.log"
filter_http_https_cmd = "tshark -i lo -o tls.keylog_file:$HOME/sslkeys.log -w output_.pcap -b packets:10 -b files:5 -b filesize:1024 " # -f \"tcp port 80 or tcp port 443\" 
merge_files_cmd = "mergecap -w merged_filtered_output.pcap output_*.pcap"

filter_log4shell_cmd = "tshark -r merged_filtered_output.pcap -Y 'tcp contains \"jndi\"' -w \"filtered_file\""
log4shell_result_cmd = ['tshark', '-r' ,'filtered_file']

# Command to trace command execution
trace_cmd_cmd = "sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf(\"Command executed: PID %d, Comm %s, Filename %s\\n\", pid, comm, str(args->filename)); }'"

# Create subprocesses with unbuffered I/O
tls_key_ps = subprocess.run(tls_key_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
filter_http_https_ps = subprocess.Popen(filter_http_https_cmd, shell=True, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def cmd_anomaly():
    trace_cmd_ps = subprocess.Popen(trace_cmd_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    while True:
        output = trace_cmd_ps.stdout.readline()
        if output == '' and trace_cmd_ps.poll() is not None:
            break
        if output:
            if "curl" in output or "wget" in output or "chmod" in output or "cmd" in output or "pwsh" in output:
                print(f"{RED}{output.strip()} !!!Log4shell activity detected!!!{RESET}")
                break
            else:
                print(output.strip())

    trace_cmd_ps.terminate()


def net_anomoly():
    merge_files_ps = subprocess.run(merge_files_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    filter_log4shell_ps = subprocess.run(filter_log4shell_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    log4shell_result_ps = subprocess.run(log4shell_result_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Decode the output from bytes to string
    output = log4shell_result_ps.stdout.decode('utf-8')

    # Check if there's any output
    if output:

        # Get the current working directory
        current_directory = os.getcwd()

        # Find all .pcap files in the current directory
        pcap_files = glob.glob(os.path.join(current_directory, '*.pcap'))

        # Loop through the list of .pcap files and delete each one
        for pcap_file in pcap_files:
            try:
                os.remove(pcap_file)
                print(f"Deleted: {pcap_file}")
            except OSError as e:
                print(f"Error deleting {pcap_file}: {e}")
                filter_http_https_ps.terminate()
        
        os.remove(os.path.join(current_directory, '*filtered*'))
        print("All .pcap files in the current directory have been deleted.")

        print(f"{RED}Suspicious log4shell found !!!{RESET}")
        print(output)
        
        cmd_anomaly()

try:
    # Read the output line by line as it is being logged
    while True:
        time.sleep(3)
        net_anomoly()

except KeyboardInterrupt:
    print("Interrupted by user, stopping...")

finally:
    filter_http_https_ps.terminate()