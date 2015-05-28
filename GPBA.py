#!/usr/bin/python

__author__ = 'agallo'


# script to get all the prefixes for a given ASN
# TODO: more flexible authentication options (username/password via command line)
# TODO: supress file create if there are no records


from jnpr.junos import Device
from argparse import ArgumentParser
import pythonwhois
import time

# setup some command line arguments

parser = ArgumentParser(description="Script to pull prefixes advertised by (or through)"
                                    " a given ASN")

parser.add_argument('ASN', metavar='ASN', type=int)

parser.add_argument('router', metavar='target_router')

parser.add_argument('-a', '--addr_family', type=int,
                    choices=[4, 6], dest='af',
                    help="Address family. -a 4 force v4 only, -a 6 force v6 only. (Default is both")

parser.add_argument('-c', '--combine', dest='combine', action='store_true',
                    help="put both address families in the same file. (Default is separate files")

parser.add_argument('-l', '--lookupASN', dest='l',
                    help="Lookup name of ASN via cymru whois. (Default is don't lookup)",
                    action="store_true")

parser.add_argument('-s', '--summarize', dest='summarize', action='store_true',
                    help="Provide a summary of hosts & /24 (v4) /64 (v4) represented by prefixes"
                         " (Default is not to summarize)")

parser.add_argument('-t', '--include-transit', dest='transit',action='store_true',
                    help='Include transit routes in query.  Changes regex from ".* ASN" to ".* ASN .*"'
                         ' (Default is do not include transit')

parser.add_argument('-u', '--user', dest='user',type=str,
                    help='username for router authentication (specify if different than current shell user)')

parser.add_argument('-k', '--key', dest='key',type=str,
                    help='full path to ssh private key (specify if different than current shell user')


args = parser.parse_args()

ASN = args.ASN
router = args.router
auser = args.user
keyfile = args.key
lookup = args.l
af = args.af
summarize = args.summarize
transit = args.transit
combine = args.combine

def getprefixes(ASN, transit, router, auser, keyfile):

    if auser is not None:
        username = auser

    if keyfile is not None:
        path2keyfile = keyfile

    dev = Device(router, user=username, ssh_private_key_file=path2keyfile)
    dev.open()
    if transit:
        ASNprefixes = dev.rpc.get_route_information(aspath_regex=".* " + str(ASN) + " .*")
    else:
        ASNprefixes = dev.rpc.get_route_information(aspath_regex=".* " + str(ASN))
    dev.close()
    return ASNprefixes



def processprefixes(ASNprefixes):
    v4prefixes = []
    v6prefixes = []
    for rtdest in ASNprefixes.iter('rt-destination'):
        if '.' in rtdest.text:
            v4prefixes.append(rtdest.text)
        elif ':' in rtdest.text:
            v6prefixes.append(rtdest.text)
    return v4prefixes, v6prefixes


def sanitycheck(ASN):
    """check to make sure the ASN is valid, and provide information about the ASN

    Check ASN type (2byte or 4byte)
    Check to see if ASN is in the private or documentation range
    Lookup and report on AS name from a whois query
    """

    # variables related to ASN ranges
    ianareserved2byteA = (0, 65535)
    ianareserved2byteB = range(64198, 64496)
    ianareserved2byteC = 23456
    ianadoc2byte = range(64496, 64512)
    ianapriv2byte = range(64512, 65534)
    ianadoc4byte = range(65536, 65552)

    ASNnotes = "Assignable"
    ASNtype = "Two byte ASN"
    ASNvalid = True

    if ASN < 0 or ASN > 4294967295:
        ASNvalid = False
        ASNnotes = "not a 32 bit integer"
        ASNtype = "not valid"
        return ASNtype, ASNnotes, ASNvalid

    if ASN >= 65536:
        ASNtype = "Four byte ASN"
        if ASN in ianadoc4byte:
            ASNnotes = "Reserved for Documentation (see RFC 5398)"
            ASNvalid = False
        elif 65552 <= ASN <= 131071:
            ASNnotes = "IANA reserved"
            ASNvalid = False
        elif 4200000000 <= ASN <= 4294967294:
            ASNnotes = "Private ASN range"
            ASNvalid = False
        elif ASN == 4294967295:
            ASNnotes = "IANA reserved"
            ASNvalid = False
        else:
            ASNvalid = True
        return ASNtype, ASNnotes, ASNvalid

    ASNtype = "Two byte ASN"
    if ASN in ianareserved2byteA:
        ASNnotes = "IANA reservered"
        ASNvalid = False
    elif ASN in ianareserved2byteB:
        ASNnotes = "IANA reservered"
        ASNvalid = False
    elif ASN in ianapriv2byte:
        ASNnotes = "Private ASN range"
        ASNvalid = False
    elif ASN in ianadoc2byte:
        ASNnotes = "Reserved for documentation"
        ASNvalid = False
    elif ASN == ianareserved2byteC:
        ASNnotes = "IANA reserved AS_TRANS.  See RFC 6793"
        ASNvalid = False
    else:
        ASNvalid = True
    return ASNtype, ASNnotes, ASNvalid


def getASname(ASN):
    whoisstring = 'AS' + str(ASN)
    ASNname = pythonwhois.net.get_whois_raw(whoisstring, server='whois.cymru.com')
    return ASNname[0][8:-1]


def summarizev4(v4prefixes):
    totalhosts = 0
    for prefix in v4prefixes:
        network, mask = prefix.split('/')
        totalhosts += 2 ** (32 - int(mask))
    twentyfourequivs = totalhosts / 256
    return totalhosts, twentyfourequivs


def summerizev6(v6prefixes):
    num64s = 0
    for prefix in v6prefixes:
        network, mask = prefix.split('/')
        num64s += 2**(64-int(mask))
    return num64s


def createfiles(ASN, v4prefixes, v6prefixes, combine):
    now = time.strftime("%d%b%Y-%H%m")
    recordsv4 = 0
    recordsv6 = 0
    if combine:
        filename = "ASN" + str(ASN) + time.strftime("%d%b%Y-%H%m") + "_v4v6"
        f = open(filename, 'w')
        for v4prefix in v4prefixes:
            f.write(v4prefix+'\n')
            recordsv4 += 1
        for v6prefix in v6prefixes:
            f.write(v6prefix+'\n')
            recordsv6 += 1
        f.close()
        print filename + " was created with " + str(recordsv4 + recordsv6) + " records"
    else:
        filename4 = "ASN" + str(ASN) + time.strftime("%d%b%Y-%H%m") + "_v4"
        filename6 = "ASN" + str(ASN) + time.strftime("%d%b%Y-%H%m") + "_v6"
        f4 = open(filename4, 'w')
        f6 = open(filename6, 'w')
        for v4prefix in v4prefixes:
            f4.write(v4prefix+'\n')
            recordsv4 += 1
        for v6prefix in v6prefixes:
            f6.write(v6prefix+'\n')
            recordsv6 += 1
        f4.close()
        f6.close()
        print filename4 + " was created with " + str(recordsv4) + " records"
        print filename6 + " was created with " + str(recordsv6) + " records"



def main():
    Atype, Anotes, Avalid = sanitycheck(ASN)
    if not Avalid:
        print "You did not provide a valid Autonomous System Number."
        print str(ASN) + " is a " + Atype + " and is " + Anotes
        return
    if lookup:
        print str(ASN) + " is an " + Anotes + " " + Atype
        print  getASname(ASN)
    ASNprefixes = getprefixes(ASN, transit, router, auser, keyfile)
    v4prefixes, v6prefixes = processprefixes(ASNprefixes)
    v4hosts, v4twentyfours= summarizev4(v4prefixes)
    if summarize:
        print "Number of v4 prefixes: " + str(len(v4prefixes))
        print "Total number of v4 hosts in these prefixes: " + str(v4hosts)
        print "Number of /24 equivalents: " + str(v4twentyfours)
        print "Number of v6 prefixes: " + str(len(v6prefixes))
        print "Number of v6 end host subnets (/64s): " + str(summerizev6(v6prefixes))
    print "v4prefixes is of type " + v4prefixes
    createfiles(ASN, v4prefixes, v6prefixes, combine)


main()
