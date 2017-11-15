#!/bin/bash
echo
echo "Script to run CS457 Final Project: Needham-Schroeder Protocol"
echo "By: Adam Slattum"
echo

rm -f dispatcher kdc/kdc kdc/logKDC.txt amal/amal amal/logAmal.txt basim/basim basim/logBasim.txt basim/bunny.mp4 
rm -f kdc/amal_key.iv kdc/amal_iv.bin kdc/basim_key.bin kdc/basim_iv.bin

echo "=============================="
echo "Compiling all source"
	gcc amal/amal.c    myCrypto.c   -o amal/amal    -lcrypto
	gcc basim/basim.c  myCrypto.c   -o basim/basim  -lcrypto
	gcc kdc/kdc.c      myCrypto.c   -o kdc/kdc      -lcrypto
	gcc genKey.c                    -o genKey       -lcrypto 
    gcc wrappers.c     dispatcher.c -o dispatcher

echo "=============================="
echo "Generating Amal and Basim Keys"
./genKey
echo

echo "Amal's Key Material:"
hexdump -C kdc/amal_key.bin
echo "Amal's IV Material:"
hexdump -C kdc/amal_iv.bin
echo

echo "Basim's Key Material:"
hexdump -C kdc/basim_key.bin
echo "Basim's IV Material:"
hexdump -C kdc/basim_iv.bin

echo "=============================="
echo "Sharing keys from KDC to Amal"
cd amal
rm -f    amal_key.bin amal_iv.bin
ln -s ../kdc/amal_key.bin  amal_key.bin
ln -s ../kdc/amal_iv.bin   amal_iv.bin
cd ..

echo "=============================="
echo "Sharing keys from KDC to Basim"
cd basim
rm -f    basim_key.bin basim_iv.bin
ln -s ../kdc/basim_key.bin  basim_key.bin
ln -s ../kdc/basim_iv.bin   basim_iv.bin
cd ..

echo "=============================="
echo "Starting the dispatcher"
./dispatcher

echo
echo "======  KDC's LOG ========="
cat kdc/logKDC.txt

echo
echo "======  Amal's  LOG  ========="
cat amal/logAmal.txt

echo
echo "======  Basim's  LOG  ========="
cat basim/logBasim.txt
echo
echo

