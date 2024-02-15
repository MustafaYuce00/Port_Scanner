import nmap
"""
print(dir(nmap))

"""
def port_scan(ip, ports, arguments=''):

    nm = nmap.PortScanner()

    nm.scan(ip, arguments=arguments + ' ' + '-p' + ports)
 


    open_ports = []



    for host in nm.all_hosts():

        print(f"Scanning: {host}")

        if 'tcp' in nm[host]:

            for port in nm[host]['tcp']:

                if nm[host]['tcp'][port]['state'] == 'open':

                    open_ports.append(port)
                    """
                    if len(open_ports) == 0:

                        print("No open ports found")

                    else:

                        print("Open ports:")

                        for port in open_ports:

                            print(port)
                    """


    return open_ports



if __name__ == '__main__':

    ip = input("Enter IP address: ")

    port_range = input("Enter port range (e.g. 1-1000 or 'all'): ")

    while port_range.lower() != 'all' and (not '-' in port_range or not port_range.replace('-', '').isdigit()):

        print("Invalid port range format!")

        port_range = input("Enter port range (e.g. 1-1000 or 'all'): ")



    ping_enabled = input("Ping enabled? (y/n): ")

    while ping_enabled.lower() != 'y' and ping_enabled.lower() != 'n':

        print("Invalid option!")

        ping_enabled = input("Ping enabled? (y/n): ")



    scan_type = input("Enter scan type (tcp/udp/icmp): ")

    while scan_type.lower() != 'tcp' and scan_type.lower() != 'udp' and scan_type.lower() != 'icmp':

        print("Invalid scan type!")

        scan_type = input("Enter scan type (tcp/udp/icmp): ")



    if port_range.lower() == 'all':

        port_range = '1-65535'



    if ping_enabled.lower() == 'n':

        arguments = '-Pn'

    else:

        arguments = ''


    if scan_type.lower() == 'udp':

        arguments += ' -sU'

    elif scan_type.lower() == 'icmp':

        arguments += ' -PE'



    open_ports = port_scan(ip, port_range, arguments)



    if len(open_ports) == 0:

        print("No open ports found")

    else:

        print("Open ports:")

        for port in open_ports:

            print(port)

