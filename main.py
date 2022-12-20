import os
import sys
import time
import re
import shodan
import json
import requests



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
    runDNScan(choiceMadeByUser)
    runTheHarvester(choiceMadeByUser)
    scan(choiceMadeByUser[0], choiceMadeByUser[1])

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


################################################################## URL SCAN ##################################################################

def scan(url, level):
    print("Scanning " + url)
    headers = {'API-Key': '0d6990d9-45e0-4421-9f96-d349f659743a', 'Content-Type': 'application/json'}
    data = {"url": url, "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))
    if response.status_code == 400:
        return
    uuid = response.json()['uuid']
    get_urlscan_result(uuid, level)


def get_urlscan_result(uuid, level):
    # Use the urlscan.io API to get the result for the given UUID
    # wait for the scan to return a http 200
    wait = 0
    while True:
        if (wait < 5):

            # clear the terminal
            os.system('cls' if os.name == 'nt' else 'clear')
            wait += 1
            print("Waiting for scan to complete" + "." * wait)
        else:
            wait = 0

        response = requests.get('https://urlscan.io/api/v1/result/' + uuid)
        if response.status_code == 200:
            break
    response = requests.get(f'https://urlscan.io/api/v1/result/{uuid}')

    # Parse the response as JSON
    data = json.loads(response.text)

    if level == 2 or level == "2":

        with open("results/full/urlscan/"+data['page']['domain'] + ".json", "w") as outfile:
            json.dump(data, outfile, indent=4)
    elif level == 1 or level == "1":

        clear_result_urlscan_api(data)


def clear_result_urlscan_api(content):
    ### relevant aggregate data
    request_info = content.get("data").get("requests")
    meta_info = content.get("meta")
    verdict_info = content.get("verdicts")
    list_info = content.get("lists")
    stats_info = content.get("stats")
    page_info = content.get("page")

    ### more specific data
    geoip_info = meta_info.get("processors").get("geoip")
    web_apps_info = meta_info.get("processors").get("wappa")
    resource_info = stats_info.get("resourceStats")
    protocol_info = stats_info.get("protocolStats")
    ip_info = stats_info.get("ipStats")

    ### enumerate countries
    countries = []
    for item in resource_info:
        country_list = item.get("countries")
        for country in country_list:
            if country not in countries:
                countries.append(country)

    ## enumerate web apps
    web_apps = []
    if web_apps_info is not None:
        for app in web_apps_info.get("data"):
            web_apps.append(app.get("app"))

    ### enumerate domains pointing to ip
    pointed_domains = []
    for ip in ip_info:
        domain_list = ip.get("domains")
        for domain in domain_list:
            if domain not in pointed_domains:
                pointed_domains.append(domain)

    ### data for summary
    page_domain = page_info.get("domain")
    page_ip = page_info.get("ip")
    page_country = page_info.get("country")
    page_server = page_info.get("server")
    ads_blocked = stats_info.get("adBlocked")
    https_percentage = stats_info.get("securePercentage")
    ipv6_percentage = stats_info.get("IPv6Percentage")
    country_count = stats_info.get("uniqCountries")
    num_requests = len(request_info)
    is_malicious = verdict_info.get("overall").get("malicious")
    malicious_total = verdict_info.get("engines").get("maliciousTotal")
    ip_addresses = list_info.get("ips")
    urls = list_info.get("urls")

    ### print data into a file named quick.domain.txt
    with open(f"results/easy/urlscan/{page_domain}.txt", "w") as f:
        f.write(f"Domain: {page_domain}\n")
        f.write(f"IP: {page_ip}\n")
        f.write(f"Country: {page_country}\n")
        f.write(f"Server: {page_server}\n")
        f.write(f"Ads Blocked: {ads_blocked}\n")
        f.write(f"HTTPS Percentage: {https_percentage}\n")
        f.write(f"IPv6 Percentage: {ipv6_percentage}\n")
        f.write(f"Country Count: {country_count}\n")
        f.write(f"Number of Requests: {num_requests}\n")
        f.write(f"Malicious: {is_malicious}\n")
        f.write(f"Malicious Total: {malicious_total}\n")
        f.write(f"IP Addresses: {ip_addresses}\n")
        f.write(f"URLs: {urls}\n")
        f.write(f"Countries: {countries}\n")
        f.write(f"Web Apps: {web_apps}\n")
        f.write(f"Domains Pointing to IP: {pointed_domains}\n")

################################################################## SHODAN ##################################################################



if __name__ == '__main__':
    main()
