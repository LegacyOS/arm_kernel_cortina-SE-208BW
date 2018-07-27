#!/bin/bash

\rm -f Bin/zImage* Bin/*.ko

cp boot/zImage Bin

find . -name *.ko -exec cp {} Bin \;

# EOF

