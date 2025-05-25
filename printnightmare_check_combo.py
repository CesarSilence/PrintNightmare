import subprocess
import argparse

def execute_script(domain, user, password, file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        
    for line in lines:
        x = line.strip()
        cmd = f"python3 printnightmare.py {domain}/{user}:'{password}'@{x} -check"
        print(f"Executing: {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print(result.stdout)
        print(result.stderr)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Execute printnightmare.py with parameters from file")
    parser.add_argument("-d", "--domain", required=True, help="Domain for the command")
    parser.add_argument("-u", "--user", required=True, help="User for the command")
    parser.add_argument("-p", "--password", required=True, help="Password for the command")
    parser.add_argument("-f", "--file_path", required=True, help="Path to the file containing target addresses")

    args = parser.parse_args()

    execute_script(args.domain, args.user, args.password, args.file_path)
