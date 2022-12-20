import os
import sys
import time


def installationController():
    # install the dependencies
    installationDnscan()
    installtionHarvester()

    # create directory installation to store the results
    # know if it's windows or linux
    if os.name == "nt":
        if not os.path.exists("results"):
            os.system("md results")
            os.system("md results\\easy")
            os.system("md results\\full")
            os.system("md results\\easy\\dnscan")
            os.system("md results\\easy\\theHarvester")
            os.system("md results\\full\\dnscan")
            os.system("md results\\full\\theHarvester")

    else:
        if not os.path.exists("results"):
            os.system("mkdir results")
            os.system("mkdir results/easy")
            os.system("mkdir results/full")
            os.system("mkdir results/easy/dnscan")
            os.system("mkdir results/easy/theHarvester")
            os.system("mkdir results/full/dnscan")
            os.system("mkdir results/full/theHarvester")



def installationDnscan():
    if not os.path.exists("dnscan"):
        os.system("git clone https://github.com/rbsec/dnscan.git")

    # install the dependencies
    print("Dependency installation DnScan...")
    time.sleep(1)
    os.system("pip install -r dnscan/requirements.txt")
    print("Installation complete!\n")


def installtionHarvester():
    if not os.path.exists("harvester"):
        os.system("git clone https://github.com/laramies/theHarvester.git")

    # install the dependencies
    print("Dependency installation TheHarvester...")
    time.sleep(1)
    os.system("pip3 install -r theHarvester/requirements.txt")
    print("Installation complete!\n")


installationController()
