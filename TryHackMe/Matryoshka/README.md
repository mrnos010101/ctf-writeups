Executive Summary

Matryoshka is a boot2root laboratory built around lateral movement, nested-environment pivoting, and container breakout techniques. It simulates a modern corporate scenario in which internal developer misconfigurations cascade into full host compromise.

This write-up documents the complete kill chain: abusing an exposed Docker socket on Level 1, navigating strict environment restrictions on Level 2 through asynchronous execution buffers, and finally achieving host takeover via direct block-device interaction on Level 3.
