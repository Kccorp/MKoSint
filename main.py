import os
import sys
import time


def main():
    choiceMadeByUser = ["", 0, ""]
    getArgs(choiceMadeByUser)


def getArgs(choiceMadeByUser):
    if len(sys.argv) == 2:

        if sys.argv[1] == "-h" or sys.argv[1] == "--help":  # Show the help menu
            displayHelp()

        elif sys.argv[1] == "--wizard" or sys.argv[1] == "-w":  # Run the wizard
            print("Wizard mode")
            userSelection(choiceMadeByUser)
            return

    if len(sys.argv) > 1:
        for i in range(1, len(sys.argv), 2):
            if sys.argv[i] == "--domain" or sys.argv[i] == "-d":
                choiceMadeByUser[0] = sys.argv[i+1]
            elif sys.argv[i] == "--level" or sys.argv[i] == "-l":
                if sys.argv[i+1] == "1" or sys.argv[i+1] == "2" or sys.argv[i+1] == "3":
                    choiceMadeByUser[1] = sys.argv[i+1]
                else:
                    print("Invalid level of scan (1, 2, or 3)")
                    exit()
            elif sys.argv[i] == "-df" or sys.argv[i] == "--domain_file":
                choiceMadeByUser[2] = sys.argv[i + 1]
            else:
                print("Invalid argument")
                print("argument = " + sys.argv[i+1] + " et i = " + str(i))
                exit()

    if choiceMadeByUser[0] == "" and choiceMadeByUser[2] == "":
        print("No domain or domain file specified")
        exit()

    if choiceMadeByUser[1] == 0:
        print("No level of scan specified")
        exit()

    if choiceMadeByUser[0] != "" and choiceMadeByUser[2] != "":
        print("You can't specify a domain and a domain file at the same time")
        exit()

    elif len(sys.argv) == 1:
        print("No arguments passed, please use --wizard or -w to run the wizard or use --help or -h to see the help menu")
        sys.exit()

    installation(choiceMadeByUser)


def displayHelp():

    print("usage : python main.py [-h] [-w] [-d domain] [-l level of scan] [-df domain file]\n")
    print("optional arguments:")
    print("-h, --help            show this help message and exit")
    print("-w, --wizard          run the wizard")
    print("-d, --domain          domain to scan")
    print("-l, --level           level of scan (1, 2, or 3)")
    print("-df, --domain_file    file containing domains to scan")
    exit(0)


def installation(choiceMadeByUser):
    if not os.path.exists("dnscan"):
        os.system("git clone https://github.com/rbsec/dnscan.git")

    # install the dependencies
    print("Dependency installation...")
    time.sleep(1)
    os.system("pip install -r dnscan/requirements.txt")
    print("Installation complete!")

    # create directory to store the results
    if not os.path.exists("results"):
        os.system("mkdir results")

    runController(choiceMadeByUser)


def runController(choiceMadeByUser):
    runDNScan(choiceMadeByUser)


def userSelection(choiceMadeByUser):
    # ask the user for the domain to scan or the file containing the domains to scan
    while True:
        print("Do you want to scan a single domain or a file containing domains ?")
        print("1. Single domain")
        print("2. File containing domains")
        choice = input("Your choice : ")
        if choice == "1":
            choiceMadeByUser[0] = input("Enter the domain to scan : ")
            break
        elif choice == "2":
            choiceMadeByUser[2] = input("Enter the file containing domains to scan : ")
            break

    while True:
        print("what level of scan would you like to run?")
        print("1. Quick")
        print("2. Basic")
        print("3. Full")
        choiceMadeByUser[1] = input("Choice: ")
        if choiceMadeByUser[1] == "1" or choiceMadeByUser[1] == "2" or choiceMadeByUser[1] == "3":
            break

    installation(choiceMadeByUser)


def runDNScan(choiceMadeByUser):
    print("Running DNScan...")
    print("This may take a while...")
    # make switch case for the different levels of scans
    if choiceMadeByUser[1] == "1":
        levelOfScan = "subdomains-500.txt"
    elif choiceMadeByUser[1] == "2":
        levelOfScan = "subdomains-1000.txt"
    elif choiceMadeByUser[1] == "3":
        levelOfScan = "subdomains-10000.txt"

    time.sleep(1)
    if choiceMadeByUser[2] == "":
        os.system("python dnscan/dnscan.py -d " + choiceMadeByUser[0] + " -t 10 -R 1.1.1.1 -o results/" + choiceMadeByUser[0] + ".txt -w dnscan/" + levelOfScan)
    else:
        os.system("python dnscan/dnscan.py -l " + choiceMadeByUser[2] + " -t 10 -R 1.1.1.1 -o results/" + choiceMadeByUser[2] + " -w dnscan/" + levelOfScan)



if __name__ == '__main__':
    main()
