#!/bin/bash

# Function to install Python and dependencies on Debian/Ubuntu
install_debian() {
    sudo apt-get update
    sudo apt-get install -y python3-pip
}

# Function to install Python and dependencies on CentOS
install_centos() {
    sudo yum install -y epel-release
    sudo yum install -y python3-pip
}

# Function to install Python and dependencies on macOS using Homebrew
install_macos() {
    if [ ! -x "$(command -v brew)" ]; then
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
    fi
    brew install python@3
}

# Check the operating system
if [ "$(uname -s)" == "Darwin" ]; then
    OS="macos"
elif [ -f /etc/os-release ]; then
    source /etc/os-release
    OS="$ID"
elif [ -f /etc/debian_version ]; then
    OS="debian"
elif [ -f /etc/redhat-release ]; then
    OS="centos"
else
    echo "Unsupported operating system"
    exit 1
fi

case "$OS" in
    debian)
        install_debian
        ;;
    centos)
        install_centos
        ;;
    macos)
        install_macos
        ;;
    *)
        echo "Unsupported operating system"
        exit 1
        ;;
esac

# Install Python packages from requirements.txt
pip3 install -r requirements.txt

# Run the main.py script
python3 main.py
