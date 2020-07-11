#!/usr/bin/env python3

from sys import argv

ALERT_FILE = "alert.bin"


def parse():
    attacks = {}
    with open(ALERT_FILE, "r") as f:
        for line in f:
            if line[:4] == "[**]":
                attack_type = line[line.find(']', line.find(']') + 1) + 2: -6]

                if attack_type not in attacks.keys():
                    attacks[attack_type] = {
                        'number_of_attacks': 1,
                        'source_ip': [],
                        'destination_ip': [],
                    }
                else:
                    attacks[attack_type]['number_of_attacks'] += 1
            elif '->' in line:
                source_ip = line[line.find(' ') + 1: line.find('->') - 1]
                attacks[attack_type]['source_ip'].append(source_ip)

                destination_ip = line[line.find('->') + 3: -1]
                attacks[attack_type]['destination_ip'].append(destination_ip)

    return attacks


if __name__ == "__main__":
    verbose_mode = True if "-v" in argv else False
    port_mode = True if "-p" in argv else False
    ip_mode = True if "-i" in argv else False

    attacks = parse()

    attacks_total = 0
    for i in attacks:
        attacks_total += attacks[i]['number_of_attacks']

    print("Snort detected a total of {0} possible intrusions, of which there are:".format(attacks_total))
    for i in attacks:
        print()
        print('\t{0} : {1} time(s)'.format(i, attacks[i]['number_of_attacks']))

        if ip_mode:
            ip_list = [i[:i.find(':')] for i in attacks[i]['source_ip']]
            print('\t\tSource IPs:')
            for j in set(ip_list):
                print('\t\t\t{0}\t{1} time(s)'.format(j, ip_list.count(j)))

            ip_list = [i[:i.find(':')] for i in attacks[i]['destination_ip']]
            print('\t\tDestination IPs:')
            for j in set(ip_list):
                print('\t\t\t{0}\t{1} time(s)'.format(j, ip_list.count(j)))

        if port_mode:
            port_list = set([i[i.find(':') + 1:] for i in attacks[i]['source_ip']])
            port_list = [int(i) for i in port_list]
            print('\t\tSource ports: {0}'.format(sorted(port_list)))

            port_list = set([i[i.find(':') + 1:] for i in attacks[i]['destination_ip']])
            port_list = [int(i) for i in port_list]
            print('\t\tDestination ports: {0}'.format(sorted(port_list)))

        if verbose_mode:
            first_line = True
            print('\t\tFrom:', end='')
            for j in set(attacks[i]['source_ip']):
                if first_line:
                    print('\t\t{0}\t{1} time(s)'.format(j, attacks[i]['source_ip'].count(j)))
                    first_line = False
                    continue
                print('\t\t\t\t{0}\t{1} time(s)'.format(j, attacks[i]['source_ip'].count(j)))

            first_line = True
            print('\t\tTowards:', end='')
            for j in set(attacks[i]['destination_ip']):
                if first_line:
                    print('\t{0}\t{1} time(s)'.format(j, attacks[i]['destination_ip'].count(j)))
                    first_line = False
                    continue
                print('\t\t\t\t{0}\t{1} time(s)'.format(j, attacks[i]['destination_ip'].count(j)))
