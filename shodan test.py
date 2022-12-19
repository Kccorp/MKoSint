import re
import shodan
import json


def clean_shodan_api_result_ip(data_list):
    clean_data = {}
    if 'ip_str' in data_list:
        clean_data['ip_str'] = data_list['ip_str']
    if 'isp' in data_list:
        clean_data['isp'] = data_list['isp']
    if 'org' in data_list:
        clean_data['org'] = data_list['org']
    if 'country_name' in data_list:
        clean_data['country_name'] = data_list['country_name']
    if 'city' in data_list:
        clean_data['city'] = data_list['city']
    if 'latitude' in data_list:
        clean_data['latitude'] = data_list['latitude']
    if 'longitude' in data_list:
        clean_data['longitude'] = data_list['longitude']
    clean_data['ports'] = []
    clean_data['vulns'] = []
    if 'os' in data_list:
        clean_data['os'] = data_list['os']
    if 'hostnames' in data_list:
        clean_data['hostnames'] = data_list['hostnames']
    if 'domains' in data_list:
        clean_data['domains'] = data_list['domains']
    if 'ports' in data_list:
        clean_data['ports'] = data_list['ports']
    if 'vulns' in data_list:
        clean_data['vulns'] = data_list['vulns']
    clean_data['data'] = []
    return clean_data


def clean_shodan_api_result_domain(domain):
    FACETS = [
        'org',
        'domain',
        'port',
        'asn',
        ('ip', 50),

        # We only care about the top 3 countries, this is how we let Shodan know to return 3 instead of the
        # default 5 for a facet. If you want to see more than 5, you could do ('country', 1000) for example
        # to see the top 1,000 countries for a search query.
        ('country', 3),
    ]

    FACET_TITLES = {
        'org': 'Top 5 Organizations',
        'domain': 'Top 5 Domains',
        'port': 'Top 5 Ports',
        'asn': 'Top 5 Autonomous Systems',
        'ip': 'Top 50 IP Addresses',
        'country': 'Top 3 Countries',
    }

    api = api_check()
    info = api.count(domain, facets=FACETS)

    with open("resume."+domain + ".json", "w") as outfile:
        json.dump(info, outfile, indent=4)


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


def shodan_domain_search(domain, level):
    api = api_check()
    print("the result will be saved in a json file named " + domain + ".json or resume" + domain + ".json if you choose a quick search")
    if level == "2":
        info = api.search(domain)
        with open(domain + ".json", "w") as outfile:
            json.dump(info, outfile, indent=4)

    else:

        clean_data = clean_shodan_api_result_domain(domain)


def shodan_ip_search(ip, level):
    api = api_check()
    print("the result will be saved in a json file named " + ip + ".json or resume" + ip + ".json if you choose a quick search")
    info = api.host(ip)
    if level == "2":
        with open(ip + ".json", "w") as outfile:
            json.dump(info, outfile, indent=4)
    else:
        clean_data = clean_shodan_api_result_ip(info)
        with open("resume" + ip + ".json", "w") as outfile:
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
    choice = input("would you like to search by IP or by domain (type 1 for ip, type 2 for domain) ?")
    level = input("you want a full search or a quick search (type 1 for summarize, type 2 for full) ?")
    if level != "1" and level != "2":
        print("invalid choice")
        exit()

    if choice == "1":
        ip = input("Enter the IP address : ")
        check_ip(ip)
        shodan_ip_search(ip, level)

    elif choice == "2":
        domain = input("Enter the domain : ")
        check_domain(domain)
        shodan_domain_search(domain, level)
    else:
        print("Invalid input")
        exit()


if __name__ == '__main__':
    main()
