# Something-Awesome-Project

This is a work in progress currently being developed as my Something Awesome Project for COMP 6841 at UNSW <br>
This project is an ARP Poisoner and DNS spoofer and will simulate a man in the middle attack

The setup involves a virtual linux machine running with Oracle VirtualBox which is in this simulation is the attacking machine. It runs a python script using scapy to send a fake ARP response and corrupt my windows machines ARP Table.

Current Progress up until Week 3 <br>
Completed setting up a virtual Linux Environment using Virtual Box. This is the attacking machine <br>
Created a Python script arpPoisoner.py which currently poisons the ARP table of the victim machine (in this case my Windows Machine) <br>

# TODOS For Week 4 and 5
 
Enable IP forwarding from the attacking machine <br>
Allow attacking machine to conduct two way ARP poisoning. Currently only poisons victim machine but not the router so router bypasses attacker <br>
Look into how to intercept request and responses with Python <br>

Mubashir Hussain
z5599894