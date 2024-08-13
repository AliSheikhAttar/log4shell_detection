import subprocess
RED = "\033[31m"
RESET = "\033[0m"
# Command to run bpftrace
trace_cmd_cmd = "sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf(\"Command executed: PID %d, Comm %s, Filename %s\\n\", pid, comm, str(args->filename)); }'"
tls_key_cmd = "export SSLKEYLOGFILE=$HOME/sslkeys.log"
filter_http_https_cmd = "tshark -i lo -o tls.keylog_file:$HOME/sslkeys.log -w output_.pcap -b packets:10 -b files:5 -b filesize:1024 " 
merge_files_cmd = "mergecap -w merged_filtered_output.pcap output_*.pcap"
filter_log4shell_cmd = "tshark -r merged_filtered_output.pcap -Y 'tcp contains \"jndi\"' -w \"filtered_file\""
log4shell_result_cmd = ['tshark', '-r' ,'filtered_file']
# Start the process and capture its output
tls_key_ps = subprocess.run(tls_key_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
trace_cmd_ps = subprocess.Popen(trace_cmd_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
filter_http_https_ps = subprocess.Popen(filter_http_https_cmd, shell=True, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
def net_anomoly():
    merge_files_ps = subprocess.run(merge_files_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    filter_log4shell_ps = subprocess.run(filter_log4shell_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    log4shell_result_ps = subprocess.run(log4shell_result_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Decode the output from bytes to string
    output = log4shell_result_ps.stdout.decode('utf-8')

    # Check if there's any output
    if output:
        print(f"{RED}Suspicious log4shell found !!!{RESET}")
        print(output)
    else:
        print("no anomaly found")
try:
    # Read the output line by line as it is being logged
    while True:
        output = trace_cmd_ps.stdout.readline()
        if output == '' and trace_cmd_ps.poll() is not None:
            break
        if output:
            if "curl" in output or "wget" in output or "chmod" in output or "cmd" in output or "pwsh" in output:
                print(f"{RED}{output.strip()} !!!Suspicious!!!{RESET}")
                net_anomoly()
            else:
                print(output.strip())
except KeyboardInterrupt:
    print("Interrupted by user, stopping...")
    trace_cmd_ps.terminate()
    filter_http_https_ps.terminate()

