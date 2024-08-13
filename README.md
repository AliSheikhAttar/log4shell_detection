# log4shell_detection

implement a log4shell detection algorithm

First we create a buffer which stores the last 10 packets on our NIC.
We log every commands constantly, whenever we face anomalous or suspicious commands executed on the system (typically does in log4shell attacks) like curl, wget & ...,  we proceed to our buffer to look for any connection for JNDI, if so, that connection is malicious and it must be blocked.

- the script is in python
- bpftrace is used to trace executed commands
- tshark is used to capture packets, other tools can also be utilized instead such as tcpdump or KRSI.
