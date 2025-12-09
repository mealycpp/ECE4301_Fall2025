import subprocess
import argparse
import re
import csv


def main():
    parser = argparse.ArgumentParser(description="A simple script to list files in a directory")
    parser.add_argument("filename", help="CSV file output")
    parser.add_argument("min_rate", type=int, help="Minimum network rate of the benchmarking (kbits)")
    parser.add_argument("max_rate", type=int, help="Maximum network rate of the benchmarking (kbits)")
    parser.add_argument("rate_step", type=int, help="Number of separate network rates to be tested per network delay value")
    parser.add_argument("min_delay", type=int, help="Minimum network delay of the benchmarking (ms)")
    parser.add_argument("max_delay", type=int, help="Maximum network delay of the benchmarking (ms)")
    parser.add_argument("delay_step", type=int, help="Number of separate network delays to be tested per network rate")
    args = parser.parse_args()

    if (args.min_rate > args.max_rate):
        print("Minimum network rate cannot be greater than maximum network rate.")
        return
    
    if (args.min_delay > args.max_delay):
        print("Minimum network delay cannot be greater than maximum network delay.")
        return
    
    rate_step = max(1, args.rate_step)
    delay_step = max(1, args.delay_step)

    csv_headers = ["Network Delay (ms)", "Network Rate (kbps)", "Kyber Exchange Time (ms)", "Diffie-Hellman Exchange Time (ms)", "Difference (ms)", "Ratio"]

    # Kyber
    csv_data = []

    current_delay = args.min_delay
    while current_delay <= args.max_delay:
        
        current_rate = args.min_rate
        while current_rate <= args.max_rate:
            print(f"Running with net. rate: {current_rate} kbits, delay: {current_delay} ms | ", end="", flush=True)
            
            # Kyber
            result = subprocess.run(["./run-client.sh", "target/debug/ECE4301-Final", f"{current_rate}kbit", f"{current_delay}ms", "client", "kyber", "10.200.1.1", "9000"], stdout=subprocess.PIPE)
            output_string = result.stdout.decode('utf-8')
            kyber_exchange_search = re.search(r"Kyber exchange time: ([\d\.]+) ms", output_string)

            if kyber_exchange_search:
                kyber_exchange_time = kyber_exchange_search.group(1)
            else:
                kyber_exchange_time = "Error"

            print(f"Kyber: {kyber_exchange_time} ms, ", end="", flush=True)

            # Diffie-Hellman
            result = subprocess.run(["./run-client.sh", "target/debug/ECE4301-Final", f"{current_rate}kbit", f"{current_delay}ms", "client", "diffie-hellman", "10.200.1.1", "9000"], stdout=subprocess.PIPE)

            output_string = result.stdout.decode('utf-8')
            dh_exchange_search = re.search(r"Diffie-Hellman exchange time: ([\d\.]+) ms", output_string)

            if dh_exchange_search:
                dh_exchange_time = dh_exchange_search.group(1)
            else:
                dh_exchange_time = "Error"

            print(f"Diffie-Hellman: {dh_exchange_time} ms", flush=True)

            csv_line = {
                csv_headers[0]: current_delay,
                csv_headers[1]: current_rate,
                csv_headers[2]: kyber_exchange_time,
                csv_headers[3]: dh_exchange_time, 
                csv_headers[4]: float(kyber_exchange_time) - float(dh_exchange_time),
                csv_headers[5]: float(kyber_exchange_time) / float(dh_exchange_time)
            }
            
            csv_data.append(csv_line)
            current_rate += rate_step

        current_delay += delay_step

    with open(args.filename, 'w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=csv_headers)
        writer.writeheader()
        writer.writerows(csv_data)

    # # Diffie-Hellman
    # diffie_hellman_data = []

    # current_delay = args.min_delay
    # while current_delay <= args.max_delay:

    #     current_rate = args.min_rate
    #     while current_rate <= args.max_rate:
    #         result = subprocess.run(["./run-client.sh", "target/debug/ECE4301-Final", f"{current_rate}kbit", f"{current_delay}ms", "client", "diffie-hellman", "10.200.1.1", "9000"], stdout=subprocess.PIPE)
            
    #         output_string = result.stdout.decode('utf-8')
    #         exchange_search = re.search(r"Diffie-Hellman exchange time: ([\d\.]+) ms", output_string)

    #         if exchange_search:
    #             exchange_time = exchange_search.group(1)
    #         else:
    #             exchange_time = "Error"

    #         csv_line = {
    #             csv_headers[0]: current_delay,
    #             csv_headers[1]: current_rate,
    #             csv_headers[2]: exchange_time
    #         }
            
    #         diffie_hellman_data.append(csv_line)
    #         current_rate += rate_step

    #     current_delay += delay_step

    # with open("diffie_hellman_benchmark.csv", 'w', newline='') as diffie_hellman_csv_file:
    #     writer = csv.DictWriter(diffie_hellman_csv_file, fieldnames=csv_headers)
    #     writer.writeheader()
    #     writer.writerows(diffie_hellman_data)


if __name__ == "__main__":
    main()