#!/bin/bash

for i in examples/*
do
    python3 pynasm.py $i
    filename="${i%.py}"
    nasm -f bin ${filename}.nasm
    rm -f $filename ${filename}.nasm 
done
