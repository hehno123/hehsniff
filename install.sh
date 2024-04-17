#!/bin/bash

g++ hehmitm/*.c lib/*.c -lpcap -lpthread -o /usr/local/sbin/hehmitm
g++ hehsniff/*.c lib/*.c -lpcap -o /usr/local/sbin/hehsniff
g++ hdnsdos/*.c lib/*.c -lpcap -o /usr/local/bin/hdnsdos

