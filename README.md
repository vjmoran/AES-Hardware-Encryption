# AES-Hardware-Encryption

I constructed a hardware accelerator to perform 128-bit AES encryption. The file lab7.c sends a plaintext message and key from a Pi to the accelerator and verifies that the cyphertext received back is correct.

The file aes.sv builds the hardware on the Cyclone IV EP4CE6E22 FPGA necessary to perform the encryption. This requires thoughtful architecture to fit a nontrivial system on the chip.
