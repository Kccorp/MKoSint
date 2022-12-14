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

    runController(choiceMadeByUser)


def displayHelp():

    print("usage : python main.py [-h] [-w] [-d domain] [-l level of scan] [-df domain file]\n")
    print("optional arguments:")
    print("-h, --help            show this help message and exit")
    print("-w, --wizard          run the wizard")
    print("-d, --domain          domain to scan")
    print("-l, --level           level of scan (1, 2, or 3)")
    print("-df, --domain_file    file containing domains to scan")
    exit(0)


def runController(choiceMadeByUser):
    # runDNScan(choiceMadeByUser)
    runTheHarvester(choiceMadeByUser)

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
        print("1. Easy")
        print("2. Full")
        choiceMadeByUser[1] = input("Choice: ")
        if choiceMadeByUser[1] == "1" or choiceMadeByUser[1] == "2" :
            break

    runController(choiceMadeByUser)


def runDNScan(choiceMadeByUser):
    print("Running DNScan...")
    print("This may take a while...")
    # make switch case for the different levels of scans
    if choiceMadeByUser[1] == "1":
        levelOfScan = "subdomains-500.txt"
        output = "results/easy/dnscan/"
    elif choiceMadeByUser[1] == "2":
        levelOfScan = "subdomains-10000.txt"
        output = "results/full/dnscan/"

    time.sleep(1)
    if choiceMadeByUser[2] == "":
        output += choiceMadeByUser[0] + ".txt"
        os.system("python dnscan/dnscan.py -d " + choiceMadeByUser[0] + " -t 10 -R 1.1.1.1 -o " + output + " -w dnscan/" + levelOfScan)
    else:
        output += choiceMadeByUser[2] + ".txt"
        os.system("python dnscan/dnscan.py -l " + choiceMadeByUser[2] + " -t 10 -R 1.1.1.1 -o " + output + " -w dnscan/" + levelOfScan)

def runTheHarvester(choiceMadeByUser):
    print("Running TheHarvester...")
    print("This may take a while...")
    # make switch case for the different levels of scans
    if choiceMadeByUser[1] == "1":
        levelOfScan = "bing"
        output = "../results/easy/theHarvester/"
    elif choiceMadeByUser[1] == "2":
        levelOfScan = "all"
        output = "../results/full/theHarvester/"

    time.sleep(1)
    if choiceMadeByUser[2] == "":
        output += choiceMadeByUser[0] + ".txt"

        os.system("cd theHarvester && python theHarvester.py -d " + choiceMadeByUser[0] + " -l 500 -b " + levelOfScan + " -f " + output)
    else:
        output += choiceMadeByUser[2] + ".txt" #A modifier pour que le nom du fichier soit le nom du domaine
        os.system("python theharvester/theHarvester.py -d " + choiceMadeByUser[2] + " -l 500 -b " + levelOfScan + " -f " + output)






if __name__ == '__main__':
    main()
