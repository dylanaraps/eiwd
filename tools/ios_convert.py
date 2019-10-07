#!/usr/bin/python3

import subprocess
import sys
import os
import argparse
from xml.etree import ElementTree

class Network:
        def __init__(self):
                self.eap_types = []
                self.outer_id = None
                self.inner_eap = None
                self.nai_realms = []
                self.cert_path = None
                self.is_hotspot = False
                self.username = None
                self.password = None
                self.ssid = None
                self.display_name = None
                self.tls_trusted_servers = []

def process_eap_config(eap_conf, network):
        for m in range(len(eap_conf)):
                if eap_conf[m].text == "AcceptEAPTypes":
                        tarray = eap_conf[m + 1]
                        for i in range(len(tarray)):
                                network.eap_types.append(tarray[i].text)

                elif eap_conf[m].text == "TTLSInnerAuthentication":
                        network.inner_eap = eap_conf[m + 1].text
                elif eap_conf[m].text == "OuterIdentity":
                        network.outer_id = eap_conf[m + 1].text
                elif eap_conf[m].text == "UserName" and args.user:
                        network.username =  eap_conf[m + 1].text
                elif eap_conf[m].text == "UserPassword" and args.passwd:
                        network.password =  eap_conf[m + 1].text
                elif eap_conf[m].text == "TLSTrustedServerNames":
                        tarray = eap_conf[m + 1]
                        for i in range(len(tarray)):
                                network.tls_trusted_servers.append(tarray[i].text)

def process_payload_array(parray):
        network = Network()

        for l in range(len(parray)):
                if parray[l].text == "NAIRealmNames":
                        nai_array = parray[l + 1]
                        for i in range(len(nai_array)):
                                network.nai_realms.append(nai_array[i].text)
                        continue
                elif parray[l].text == "IsHotspot":
                        if parray[l + 1].tag.lower() == "true":
                                network.is_hotspot = True
                        else:
                                network.is_hotspot = False
                elif parray[l].text == "SSID_STR":
                        network.ssid = parray[l + 1].text
                elif parray[l].text == "DisplayedOperatorName":
                        network.display_name = parray[l + 1].text
                elif parray[l].text == "EAPClientConfiguration":
                        process_eap_config(parray[l + 1], network)

        return network

def process_payload(payload):
        networks = []
        for k in range(len(payload)):
                if payload[k].tag != "dict":
                        continue

                n = process_payload_array(payload[k])
                if n:
                        networks.append(n)

        return networks


def write_network(network, root_ca_path):
        global cert_path
        output = ""
        eap = None

        # TODO: Handle multiple EAP types?
        if len(network.eap_types) < 1:
                print("Not configuring open network %s" % network.ssid)
                return

        if network.eap_types[0] == '21':
                eap = 'TTLS'
        elif network.eap_types[0] == '25':
                eap = 'PEAP'

        if not eap:
                print("TTLS or PEAP config was not found in XML")
                return

        if not network.inner_eap:
                print("No inner EAP method found in XML")
                return

        if network.is_hotspot and len(network.nai_realms) == 0:
                print("No NAI realms found in XML")
                return

        output = "[Security]\n"
        output += "EAP-Method=%s\n" % eap

        # Use OuterIdentity if specified. But if not use "anonymous". Some AP's
        # do not like an empty identity packet and will timeout.
        if network.outer_id:
                output += "EAP-Identity=%s\n" % network.outer_id
        else:
                output += "EAP-Identity=anonymous\n"

        if root_ca_path:
                output += "EAP-%s-CACert=embed:root_ca\n" % eap

        output += "EAP-%s-Phase2-Method=Tunneled-%s\n" % \
                                                        (eap, network.inner_eap)

        if network.username:
                output += "EAP-%s-Phase2-Identity=%s\n" % \
                                                        (eap, network.username)

        if network.password:
                output += "EAP-%s-Phase2-Password=%s\n" % \
                                                        (eap, network.password)

        if len(network.tls_trusted_servers) > 0:
                output += "EAP-%s-ServerDomainMask=" % eap
                output += ';'.join(network.tls_trusted_servers)
                output += '\n'

        if network.display_name:
                name = network.display_name
        elif network.ssid:
                name = network.ssid
        else:
                name = "NameUnknown"

        if network.is_hotspot:
                conf_file = iwd_dir + '/hotspot/' + \
                                name + '.conf'
                output += "[Hotspot]\n"
                output += "NAIRealmNames="
                output += ','.join(network.nai_realms)
                output += "\n"
                output += "Name=%s\n" % name

        else:
                conf_file = iwd_dir + '/' + name + '.8021x'

        # Some AP's require older protocol versions. There should be no harm in
        # setting this all the time.
        output += "[EAPoL]\n"
        output += "ProtocolVersion=1\n"

        output += "\n"

        if root_ca_path:
                output += "[@pem@root_ca]\n"
                with open(root_ca_path) as f:
                        output += f.read()

        print("Provisioning network %s\n" % conf_file)

        if args.verbose:
                print(output)

        with open(conf_file, 'w+') as f:
                f.write(output)

def find_root_ca(chain):
        def cleanup(certs):
                for c in certs:
                        os.remove(c)

        def parse_cert_chain(file):
                certs = []
                in_cert = False
                current = ""
                f = open(file, 'r')
                for l in f:
                        if '-----BEGIN CERTIFICATE-----' in l:
                                if in_cert:
                                        print("invalid BEGIN")
                                        exit()
                                in_cert = True
                        elif '-----END CERTIFICATE-----' in l:
                                if not in_cert:
                                        print("invalid END")
                                        exit()
                                in_cert = False
                                current += l
                                certs.append(current)
                                current = ""
                                continue

                        current += l

                return certs

        def find_root_ca_path(hash):
                path = '/etc/ssl/certs/%s.0' % hash
                if os.path.exists(path):
                        return os.path.realpath(path)

                return None

        #
        # Parse each cert out of the chain.
        #
        certs = parse_cert_chain(chain)
        files = []
        subjects = []
        self_signed = None

        if len(certs) < 1:
                print("No certs found")
                exit()

        #
        # Write each cert into an intermediate#.pem file, get subject and see if
        # any are self-signed (Root CA). If one is self signed, save this file
        # to be used later when verifying the chain.
        #
        for index, c in enumerate(certs):
                with open("/tmp/intermediate" + str(index) + ".pem", 'w+') as f:
                        f.write(c)

                        files.append("/tmp/intermediate%d.pem" % index)

                with open(os.devnull, 'w') as devnull:
                        proc = subprocess.Popen(['openssl', 'x509', '-subject',
                                        '-hash', '-issuer_hash', '-noout', '-in',
                                        '/tmp/intermediate%d.pem' % index],
                                        stdout=subprocess.PIPE, stderr=devnull)

                result, err = proc.communicate()
                results = result.decode("utf-8").split('\n')

                sub = results[0]
                own_hash = results[1]
                issuer_hash = results[2]

                #
                # Get rid of "depth=#" openssl output
                #
                sub = sub[sub.index('C ='):].strip()
                subjects.append(sub)

                if own_hash == issuer_hash:
                        self_signed = '/tmp/intermediate%d.pem' % index

        #
        # Let openssl verify and print the subject of the cert chain. If there
        # is a self signed cert we want openssl to bypass looking in the cert
        # store (-no-CApath), and provide this CA (-CAfile). Otherwise, let
        # openssl verify the chain as usual.
        #
        if not self_signed:
                with open(os.devnull, 'w') as devnull:
                        proc = subprocess.Popen(['openssl', 'verify',
                                        '-show_chain', '-untrusted', chain,
                                        '/tmp/intermediate0.pem'],
                                        stdout=subprocess.PIPE, stderr=devnull)
        else:
                with open(os.devnull, 'w') as devnull:
                        proc = subprocess.Popen(['openssl', 'verify',
                                        '-show_chain', '-no-CApath', '-CAfile',
                                        self_signed, '-untrusted', chain,
                                        '/tmp/intermediate0.pem'],
                                        stdout=subprocess.PIPE, stderr=devnull)

        results, err = proc.communicate()
        results = results.decode("utf-8").strip().split('\n')

        #
        # We only want lines starting with depth=
        #
        results = [e for e in results if e.startswith('depth=')]

        print("Found %d certs in chain" % len(results))

        #
        # Get rid of prepended "depth=#"
        #
        ca_sub = results[-1]
        ca_sub = ca_sub[ca_sub.index('C ='):].strip()

        #
        # The last cert in the chain will either be a Root CA, or issued by a
        # Root CA. If we find a matching subject in our previous -show_chain
        # command we know there is a Root CA in the chain, if not we need to
        # find the Root CA on the system.
        #
        ca_cert_index = len(results) - 2

        for i, sub in enumerate(subjects):
                if ca_sub == sub:
                        print("Root CA found in chain, index=%d" % i)
                        ca_cert_index = i

        #
        # Now that we have this last cert, check if its a Root CA or not by
        # checking if its hash matches the issuer hash.
        #
        with open(os.devnull, 'w') as devnull:
                proc = subprocess.Popen(['openssl', 'x509', '-hash',
                                '-issuer_hash', '-noout', '-in',
                                '/tmp/intermediate%d.pem' % ca_cert_index],
                                stdout=subprocess.PIPE, stderr=devnull)
        hashes, err = proc.communicate()
        hashes = hashes.decode('utf-8').strip().split('\n')

        own = hashes[0]
        issuer = hashes[1]

        if own == issuer:
                #
                # Since this is a Root CA, we should already have a copy on the
                # system. Verify the hash links to a system cert.
                #
                path = find_root_ca_path(issuer)
                if path is not None:
                        print("Verified Root CA exists: %s" % path)
                else:
                        print("Root CA in chain could not be found on system")
                        return None

                cleanup(files)
                return path

        print("Root CA not found in cert chain, looking on system")

        #
        # The final cert in the chain was not a Root CA, check if we have a Root
        # CA on the system matching the last certs issuer hash.
        #
        path = find_root_ca_path(issuer)
        if path is None:
                print("Could not find issuer %s" % issuer)
                return None

        with open(os.devnull, 'w') as devnull:
                proc = subprocess.Popen(['openssl', 'x509', '-hash',
                                        '-issuer_hash', '-noout', '-in', path],
                                        stdout=subprocess.PIPE, stderr=devnull)

        hashes, err = proc.communicate()
        hashes = hashes.decode('utf-8').strip().split('\n')

        own = hashes[0]
        issuer = hashes[1]

        if own == issuer:
                path = find_root_ca_path(issuer)
                if path is not None:
                        print("Verified Root CA exists: %s" % path)
                else:
                        print("Root CA could not be found on system")
                        return None

        cleanup(files)

        return path

iwd_dir='/var/lib/iwd'
cert_path = None

description = '''
Convert iOS mobileconfig file to IWD format. Currently only TTLS and PEAP are
supported. Inner methods supported are PAP, CHAP, MSCHAP, MSCHAPv2.
'''

parser = argparse.ArgumentParser(description=description)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-i', '--input', nargs='?', metavar='mobileconfig',
                help='iOS mobileconfig file')
parser.add_argument('-o', '--iwd-out', nargs='?', metavar='dir',
                help='IWD configuration directory (default /var/lib/iwd)')
parser.add_argument('-u', '--user', action='store_true',
                help='Store username in provisioning file')
parser.add_argument('-p', '--passwd', action='store_true',
                help='Store password (plaintext) in provisioning file')
parser.add_argument('-v', '--verbose', action='store_true',
                help='Enable verbose output')
group.add_argument('-x', '--xml', nargs='?',
                help='Directly pass XML')

args = parser.parse_args()

if args.iwd_out:
        iwd_dir = args.iwd_out

if args.input:
        with open(os.devnull, 'w') as devnull:
                proc = subprocess.Popen(['openssl', 'cms', '-in', args.input, '-inform',
                                        'der', '-verify', '-noverify'],
                                        stdout=subprocess.PIPE, stderr=devnull)

        xml, err = proc.communicate()

        xml = xml.decode('utf-8')
else:
        with open(args.xml) as f:
                xml = f.read()

if args.verbose:
        print(xml)

if args.input:
        subprocess.call(['openssl', 'cms', '-in', args.input, '-inform', 'der',
                        '-outform', 'pem', '-noout', '-cmsout', '-certsout',
                        '/tmp/certchain.crt'])

root = ElementTree.fromstring(xml)

for i in range(len(root)):
        for j in range(len(root[i])):
                if root[i][j].text != "PayloadContent":
                        continue
                if (root[i][j + 1].tag != "array"):
                        continue

                payload = root[i][j + 1]
                nets = process_payload(payload)

if args.input:
        root_ca_path = find_root_ca('/tmp/certchain.crt')
else:
        root_ca_path = None

for n in nets:
        write_network(n, root_ca_path)
