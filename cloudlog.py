import subprocess

# Path to the bash file
bash_file_path = 'S3nder.sh'

# Command to run the bash file with sudo
command = ['sudo', 'bash', bash_file_path]

# Run the command
subprocess.call(command)
