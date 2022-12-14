import re
import shodan
import json


def clean_shodan_api_result(data):
    clean_data = []

    for item in data:
        clean_item = {}

        clean_item["ip"] = item["ip_str"]
        clean_item["port"] = item["port"]

        clean_data.append(clean_item)

    # Sort the list of cleaned and ordered data by IP address and port
    clean_data.sort(key=lambda x: (x["ip"], x["port"]))

    return clean_data


def shodan_search(ip):
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

    info = api.host(ip)

    clean_data = clean_shodan_api_result(info["data"])

    print(json.dumps(clean_data, indent=4))

    #
    # with open("sample.json", "w") as outfile:
    #     json.dump(info, outfile, indent=4)

def check_ip(ip):
    IPV4_REGEX = r"^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if re.match(IPV4_REGEX, ip):
        return True
    else:
        print("Invalid IP address")
        exit()

def main():
    input("Press Enter to continue...")
    print("enter the ip address to scan")
    ip = input("ip address: ")
    check_ip(ip)
    # print("enter the api key")
    # api_key=input("api key: ")
    shodan_search(ip)


if __name__ == '__main__':
    main()




