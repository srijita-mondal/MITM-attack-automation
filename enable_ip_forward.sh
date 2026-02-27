#!/bin/bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
echo "[+] IP forwarding enabled"
