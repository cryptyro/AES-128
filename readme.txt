AESFINAL: Contains our Rijndael AES Implementation in C (with various modes of operations)
	1) Header Compilation: gcc -c utils.c
						   gcc -c moops.c
	This should generate "utils.o" and "moops.o"
	
	2) Compilation with static linking: gcc -o AES AES.c utils.o moops.o -lcrypto
																		 (for openssl)
	3) Execution: Mentioned in the "print_usage" function.
	./AES e 1 test.pdf out.pdf YELLOW_SUBMARINE
	 <operation> <mode_of_operation> <inputfile> <outputfile> <key>
	 
	 
AESLUT: A simple Look up Table implementation as proposed by Rijndael
	gcc -o lutaes lutaes.c && ./lutaes
	

AES-NI: Leveraging the instruction set introduced by intel.
	gcc -maes -o aesni aesni.c && ./aesni
	

InverseInGF2^8: Generation of S-BOX using field operations
	gcc -o sbox sbox.c && ./sbox
