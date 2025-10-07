There are effectively 2 things being done for each run:
1) Encrypting the message "Hi this is plain text" and displaying the execution time, throughput, and total Latency using the specific encryption method.
2) Running the specific encryption method for 3 seconds using block sizes of 16 kB as to reference it to the speed test done by doing "openssl speed -evp aes-256-gcm" in the terminal. (Sha 256 in this case)
