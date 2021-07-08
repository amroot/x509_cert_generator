#!/usr/bin/env python3

# x509_cert_generator.py
#
# By Robert Gilbert (amroot.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from OpenSSL import crypto
from OpenSSL import SSL
from random import randint

def certificate_generator(**kwargs):
    """Generates an x509 certificate.
    Param cert_file (str): the name of the certificate file
    Param chain_file (str): the name of the file that will contain both the key and certificate. 
        This can be used with httpserver.
    Param common_name (str): the domain for the certificate
    Param country_name (str): The country of use
    Param email_address (str): Email address for certificate
    Param key_file (str): the file to store the private key
    Param key_length (int): the length of the key
    Param organization_name (str): the name of the organization
    Param organization_unit_name (str): department,
    Param serial_number (str): the serial number that is less than 20 bytes to use.
        Should be unique but doesn't matter. 
    Param state_or_province_name (str),
    Param validity_end (int): Seconds until expired
    Param validity_start (int): Seconds to start
    """
    public_key = crypto.PKey()
    public_key.generate_key(crypto.TYPE_RSA, kwargs['key_length'])
    certificate = crypto.X509()
    certificate.get_subject().C = kwargs['country_name']
    certificate.get_subject().CN = kwargs['common_name']
    certificate.get_subject().emailAddress = kwargs['email_address']
    certificate.get_subject().O = kwargs['organization_name']
    certificate.get_subject().OU = kwargs['organization_unit_name']
    certificate.get_subject().ST = kwargs['state_or_province_name']
    certificate.gmtime_adj_notAfter(kwargs['validity_end'])
    certificate.gmtime_adj_notBefore(kwargs['validity_start'])
    certificate.set_serial_number(int(kwargs['serial_number']))
    certificate.set_issuer(certificate.get_subject())
    certificate.set_pubkey(public_key)
    certificate.sign(public_key, 'sha512')
    cert = crypto.dump_certificate(crypto.FILETYPE_PEM, certificate).decode('utf-8')
    private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, public_key).decode('utf-8')
    chain = private_key + cert
    cert_file = kwargs['cert_file']
    key_file = kwargs['key_file']
    chain_file = kwargs['chain_file']
    with open(cert_file, 'wt') as fh:
        fh.write(cert)
        print(f'[+] wrote {cert_file}')
    with open(key_file, 'wt') as fh:
        fh.write(private_key)
        print(f'[+] wrote {key_file}')
    with open(chain_file, 'wt') as fh:
        fh.write(chain)
        print(f'[+] wrote {chain_file}')


def serial_number(name = "amroot.com"):
    """Returns a hex serial number by converting each letter to ASCII
    Param name (str): name to include in serial number
    """
    serial = ''
    for c in name:
        # the serial number should be less than 20
        if len(c) >= 17:
            break
        serial += str(ord(c))
    # make sure
    serial = str(serial)[:19]
    while len(serial) < 19:
        serial += randint(0,9)
    print(f'[i] Serial: {serial}')
    return serial


def main():
    kwargs = {
        'cert_file' : 'server.crt',
        'chain_file' : 'certificate-chain.pem',
        'common_name' : 'attackersite.com',
        'country_name' : 'US',
        'email_address' : 'test@example.com',
        'key_file' : 'certificate.key',
        'key_length' : 4096,
        'organization_name' : 'Test Org',
        'organization_unit_name' : 'IT',
        'serial_number' : serial_number(),
        'state_or_province_name' : 'CA',
        'validity_end' : 2*365*24*60*60,
        'validity_start' : 0
    }

    certificate_generator(**kwargs)


if __name__ == "__main__":
	main()
