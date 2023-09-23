# import subprocess

# # Run the 'brew list --versions' command
# command = 'brew list --versions'
# try:
#     result = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.STDOUT)
#     print(f"result {result}")
# except subprocess.CalledProcessError as e:
#     result = e.output

# # Write the result to a file
# output_file = 'brew_list_versions.txt'
# with open(output_file, 'w') as file:
#     file.write(result)

# print(f"Output written to {output_file}")

import subprocess

# Define the shell command you want to execute
command = "ls -l"

# Execute the command using subprocess.run
result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# Check the return code to see if the command was successful (0 indicates success)
if result.returncode == 0:
    print("Command executed successfully")
    print("Output:")
    print(result.stdout)
else:
    print("Command failed")
    print("Error:")
    print(result.stderr)