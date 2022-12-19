import re
import shodan
import json


def clean_shodan_api_result_ip(data):
    clean_data = []

    for item in data:
        clean_item = {}

        clean_item["ip"] = item["ip_str"]
        clean_item["port"] = item["port"]

        clean_data.append(clean_item)

    clean_data.sort(key=lambda x: (x["ip"], x["port"]))

    return clean_data

# def clean_shodan_api_result_domain(data):
#     clean_data = []
#
#     for item in data:
#         clean_item = {}
#
#         clean_item["ip"] = item["ip_str"]
#         clean_item["port"] = item["port"]
#
#         clean_data.append(clean_item)
#
#     clean_data.sort(key=lambda x: (x["ip"], x["port"]))
#
#     return clean_data

def api_check():
    api_key = "API_KEY"
    with open("conf.txt", "r") as f:
        for line in f:
            if "Shodan_api_key" in line:
                api_key = line.split(":")[1]
                break

    if api_key == "API_KEY":
        print("No API key found in conf.txt, please respect the format Shodan_api_key:API_KEY")
        exit()
    api = shodan.Shodan(api_key)
    return api


def shodan_domain_search(domain):
    api = api_check()
    info = api.search(domain)

    clean_data = clean_shodan_api_result_domain(info["data"])

    print(json.dumps(clean_data, indent=4))


    with open(domain+".json", "w") as outfile:
        json.dump(clean_data, outfile, indent=4)


def shodan_ip_search(ip):
    api = api_check()

    info = api.host(ip)

    clean_data = clean_shodan_api_result_ip(info["data"])

    # print(json.dumps(clean_data, indent=4))


    with open(ip+".json", "w") as outfile:
        json.dump(clean_data, outfile, indent=4)


def check_ip(ip):
    IPV4_REGEX = r"^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if re.match(IPV4_REGEX, ip):
        return True
    else:
        print("Invalid IP address")
        exit()
def check_domain(domain):
    DOMAIN_REGEX = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"
    if re.match(DOMAIN_REGEX, domain):
        return True
    else:
        print("Invalid domain")
        exit()

def main():
    input("Press Enter to continue...")
    choice=input("would you like to search by IP or by domain (type 1 for ip, type 2 for domain) ?")
    if choice == "1":
        ip = input("Enter the IP address : ")
        check_ip(ip)
        shodan_ip_search(ip)
    elif choice == "2":
        domain = input("Enter the domain : ")
        check_domain(domain)
        shodan_domain_search(domain)
    else:
        print("Invalid input")
        exit()


if __name__ == '__main__':
    main()
