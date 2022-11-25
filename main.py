import os
import sys
import time
import pip


def main():
    installation()


def installation():
    if not os.path.exists("dnscan"):
        os.system("git clone https://github.com/rbsec/dnscan.git")

    # install the dependencies
    print("Dependency installation...")
    time.sleep(1)
    os.system("cd dnscan && pip install -r requirements.txt")
    print("Installation complete!")

# def userSelection(domain, ):


if __name__ == '__main__':
    main()
