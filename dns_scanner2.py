__author__ = "Mathias Pettersen"
__copyright__ = "Copyright (C) 2021 Mathias Pettersen"
__license__ = "Public Domain"
__version__ = "1.0"

import dns.resolver
import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.rdatatype
import csv

"""

A DNS and DNSSEC scanner to showcase what records the domains have,
and if they have DNSSEC enabled. It also shows information about
the encryption methods of DNSSEC and its TTL value.

"""
# Creates text file with TTL value of the domains
ttl_value_txtfile = open("ttl_value_textfile.txt", "w")

# Creates text file with a number corresponding to the cryptographic value used
cryptographic_value_txtfile = open("cryptographic_value_textfile.txt", "w")


# CHANGE PATH TO YOUR PATH FILE (should be a domain name list)
with open("C:/Users/mathi/OneDrive/Noroff/Noroff/Year 3/FDP/pythonProject_current/Scandinavia/scandinavia_high_ed.txt", "r") \
        as domain_name_file:
    headings = ["DOMAIN NAME", "TLD", "TTL", "DNSSEC Y/N", "DNSSEC ALG NO", "ALGORITHM"]

    # Create the CSV document
    with open('CSV_file.csv', mode='w', newline='') as file:
        writer = csv.writer(file, quotechar='"', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(headings)

        for line in domain_name_file:

            contents = line.strip()

            # answers = dns.resolver.resolve(contents, "MX", raise_on_no_answer=False)


            # Getting information from the "SOA" (Start of Authority) record
            answers = dns.resolver.resolve(contents, "SOA", raise_on_no_answer=False)

            print(contents + "    " + str(answers.rrset.ttl))

            for answer in answers:
                print("\n\n***********")
                print("***********")
                print(contents)
                print("***********")
                print("***********")
                print("\nMX -------------------------------------------")
                print(answer) # Mail Exchange server
                print("MX ---------\n")

            answers = dns.resolver.resolve(contents, "NS", raise_on_no_answer=False)
            for answer in answers:
                if answer is not None:
                    print("NS -------------------------------------------")
                    print(answer) # Name server
                    print("NS ---------\n")

            answers = dns.resolver.resolve(contents, "A", raise_on_no_answer=False)
            for answer in answers:
                print("A -------------------------------------------")
                print(answer) # IPv4 address
                print("A ---------\n")

            answers = dns.resolver.resolve(contents, "AAAA", raise_on_no_answer=False)
            for answer in answers:
                print("AAAA -------------------------------------------")
                print(answer) #IPv6 address
                print("AAAA ---------\n")

            answers = dns.resolver.resolve(contents, "SOA", raise_on_no_answer=False)
            for answer in answers:
                print("SOA -------------------------------------------")
                print(answer) # Start of Authority record
                print("SOA ---------\n")

            answers = dns.resolver.resolve(contents, "DNSKEY", raise_on_no_answer=False)
            for answer in answers:
                # new_ans = answer
                print("DNSKEY -------------------------------------------")
                print(answer) # DNS key
                print("DNSKEY ---------\n")

            if answers.rrset is not None:
                print("RRSET -----------------------------------------------")
                print(answers.rrset.ttl) # Resource Record set
                print("RRSET -------------\n")

            if answers.rrset is not None:
                print("RRSET NAME -----------------------------------------------")
                print(answers.rrset.rdtype) # Resource Record name
                print("RRSET NAME -------------\n")

            # print("\nDNSSEC DNSSEC DNSSEC --------- DNSSEC DNSSEC DNSSEC")




            def get_dnssec(dns_resolver_dnssec, domain_name2):

                """

                Function checks DNSSEC validation

                """

                # Check the input and add missing . if needed

                global ttl, dnssec_keyy
                if not domain_name2.endswith("."):
                    domain_name2 = domain_name2 + "."

                # get the primary nameservers for the target domain
                response = dns_resolver_dnssec.resolve(domain_name2, dns.rdatatype.NS)
                name_server = response.rrset[0]  # name
                try:
                    response = dns_resolver_dnssec.resolve(str(name_server), dns.rdatatype.A)
                except:
                    raise Exception("timeout")
                name_server_address = response.rrset[0].to_text()  # IPv4

                # get the DNSKEY for the zone
                request = dns.message.make_query(domain_name2,
                                                 dns.rdatatype.DNSKEY,
                                                 want_dnssec=True)

                # send the query
                response = dns.query.udp(request, name_server_address, timeout=1.0)
                if response.rcode() != 0:
                    raise Exception("get_dnssec_status: response code was not 0")
                # the answer should contain both DNSKEY and RRSIG(DNSKEY)

                answer = response.answer
                # if len(answer) != 2:
                #    # an exception was raised
                #    raise Exception("get_dnssec_status: length of answer != 2, " +
                #                    str(len(answer)))

                # validate the DNSKEY signature

                name = dns.name.from_text(domain_name2)

                # print("----------------------------------------------")
                # print(domain_name2)
                # print(response)
                # print("**********************************************")
                # print(request)
                # print(answer)

                # print("----------------------------------------------")

                # Dictionary to map the numbers to algorithms
                algorithms = {
                    "1": "RSAMD5",
                    "2": "DH",
                    "3": "DSA",
                    "4": "ECC",
                    "5": "RSASHA1",
                    "6": "DSANSEC3SHA1",
                    "7": "RSASHA1NSEC3SHA1",
                    "8": "RSASHA256",
                    "10": "RSASHA512",
                    "12": "ECCGOST",
                    "13": "ECDSAP256SHA256",
                    "14": "ECDSAP384SHA384",
                    "15": "ED25519",
                    "16": "ED448",
                    "252": "INDIRECT",
                    "253": "PRIVATEDNS",
                    "254": "PRIVATEOID"
                }

                # If domain uses DNSSEC, run this
                if answer:

                    soa_record = dns.resolver.resolve(contents, "SOA", raise_on_no_answer=False)

                    ttl_value = str(soa_record.rrset.ttl)

                    dnssec_key = dns.resolver.resolve(contents, "DNSKEY", raise_on_no_answer=False)

                    for row in dnssec_key:
                        dnssec_keyy = row

                    print("ok\n" + str(dnssec_keyy) + "\nok")

                    sep = '.'
                    tld = "." + domain_name.split(sep, 1)[-1]

                    substring = "[<25"
                    # substring1 = "6" or "7"
                    algo = str(answer).split(substring, 1)[1].strip()

                    input1 = [str(domain_name), str(tld), str(ttl_value), str("y"), str(algo[4:6].strip()),
                              str(algorithms[algo[4:6].strip()])]

                    ttl_value_txtfile.write(str(ttl_value) + "\n")
                    cryptographic_value_txtfile.write(str(algo[4:6].strip()) + "\n")
                    writer.writerow(input1)


                # If domain does NOT use DNSSEC, run this:
                else:
                    soa_record = dns.resolver.resolve(contents, "SOA", raise_on_no_answer=False)
                    ttl_value = str(soa_record.rrset.ttl)

                    sep = '.'
                    tld = "." + domain_name.split(sep, 1)[-1]

                    input2 = [str(domain_name), str(tld), str(ttl_value), str("n"), str(""), str("")]

                    writer.writerow(input2)
                    ttl_value_txtfile.write(str(ttl_value) + "\n")

                try:

                    dns.dnssec.validate(answer[0], answer[1], {name: answer[0]})
                except dns.dnssec.ValidationFailure:
                    # an exception was raised
                    raise Exception("get_dnssec_status: Failed validation.")

                else:
                    # valid DNSSEC signature found
                    return


            if __name__ == "__main__":

                dns_resolver = dns.resolver.Resolver()
                # set a default nameserver
                dns_resolver.nameservers = ["8.8.8.8"] # Google server
                dns_resolver.timeout = 1.0
                dns_resolver.lifetime = 1.0
                domain_name = contents

                try:
                    get_dnssec(dns_resolver, domain_name)

                    # print("\nDNSSEC VALID------------------------------------------- ")
                    # print(domain_name)

                    # print("DNSSEC VALID-------------")

                except:

                    pass
                    # print("\nFAILURE DNSSEC-------------------------------------")
                    # print(domain_name + " error")

                    # print("FAILURE DNSSEC------------")

    # host_reversed = dns.reversename.from_address("216.58.211.142")
    # print("\n------Reverse lookup " + host_reversed.__str__())
    # print("\n\n------Lookup from reversed lookup " + dns.reversename.to_address(host_reversed).encode().decode())
