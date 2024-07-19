import os
import subprocess
from shutil import copyfile
from distutils.dir_util import copy_tree
from cryptography.x509 import ReasonFlags, Certificate
from cryptography.x509.ocsp import OCSPCertStatus
import datetime
from fastapi.datastructures import UploadFile
from fastapi.responses import FileResponse
import pexpect

from typing import List, Optional, Tuple, MutableMapping, Any, Dict
from util import create_dir, load_file, load_cert_pem_file, remove_path_and_extension, write_file_contents, delete_dir


class CertificateAuthority:
    """ This is a proxy to the Cerificate Authority and provides
        an interface for the application.
    """
    def __init__(self):
        self.ca: str
        self.ca_dir: str
        self.log_file: str
        self.issued_dir: str
        self.csr_dir: str
        self.ca_cert: str
        self.certs_by_serial_no: str
        self.revoked_certs_by_serial_no: str

        self.server_cert_template_file: str
        self.server_cert_template: str
        self.ocsp_cert_template_file: str
        self.ocsp_cert_template: str

    def set_config(self, config: MutableMapping[str, Any]):
        self.ca = config["ca"]
        self.ca_dir = config["ca_dir"]
        self.log_file = config["log_file"]
        self.issued_dir = config["issued_dir"]
        self.csr_dir = config["csr_dir"]
        self.ca_cert = config["ca_cert"]
        self.certs_by_serial_no = config["certs_by_serial_no"]
        self.revoked_certs_by_serial_no = config["revoked_certs_by_serial_no"]

        self.server_cert_template_file = config["server_cert_template_file"]
        self.server_cert_template = config["server_cert_template"]

        self.ocsp_cert_template_file = config["ocsp_cert_template_file"]
        self.ocsp_cert_template = config["ocsp_cert_template"]

        # Other setup stuff
        self.setup_templates()

    def setup_templates(self):
        # Create dir for csrs, if required
        create_dir(self.csr_dir)
        write_file_contents(self.server_cert_template_file, self.server_cert_template)
        write_file_contents(self.ocsp_cert_template_file, self.ocsp_cert_template)

    def setup_ca(self, ca_name: str) -> Dict[str, Any]:
        """ Create a new certificate authority with the given CA name.
            This replaces the previous setup.sh script.
        """
        # Delete csr dir
        delete_dir(self.csr_dir)
        # ln -s /usr/share/easy-rsa/* /home/root/easy-rsa
        try:
            copy_tree("/usr/share/easy-rsa", self.ca_dir)
        except FileExistsError as e:
            print(f"directory {self.ca_dir} exists")
            print(e)
            pass
        # cp vars /home/root/easy-rsa
        copyfile("/app/src/vars", os.path.join(self.ca_dir, "vars"))
        # cd /home/root/easy-rsa
        os.chdir(self.ca_dir)

        # ./easyrsa init-pki
        signer = pexpect.spawn("./easyrsa init-pki")
        i = signer.expect(["Confirm removal: ", pexpect.EOF])
        if i == 0:
            signer.sendline("yes")

        # yes "\n" | ./easyrsa build-ca nopass
        buildca = pexpect.spawn("./easyrsa build-ca nopass")
        buildca.expect(r"\[Easy-RSA CA\]:")
        buildca.sendline(ca_name)

        self.setup_templates()
        return {
            "result": "success - now restart the service"
        }

    def _create_csr(self, subject_name: str, subject: str) -> None:
        """ Generate a certificate signing request.

            mkdir practice-csr
            cd practice-csr
            openssl genrsa -out my.key
            openssl req -new -key my.key -out my.req -subj /C=UK/ST=Greater/ London/L=London/O=nChain/OU=Research/CN=my-server
        """
        key = os.path.join(self.csr_dir, f"{subject_name}.key")
        req = os.path.join(self.csr_dir, f"{subject_name}.req")

        # Generate private key
        p = subprocess.run(["openssl", "genrsa", "-out", key], capture_output=True)
        p.check_returncode()
        # Generate request
        p = subprocess.run(["openssl", "req", "-new", "-key", key, "-out", req, "-subj", subject], capture_output=True)
        p.check_returncode()

    def _sign_csr(self, subject_name: str, cert_type="server") -> str:
        """ Given the subject_name sign the associated csr
            and return the path to the certificate file.

            cd ../easy-rsa
            ./easyrsa import-req ../practice-csr/my.req my-server
            yes "yes"| ./easyrsa sign-req server my-server
        """
        req = os.path.join(self.csr_dir, f"{subject_name}.req")

        # Import the request
        p = subprocess.run(["./easyrsa", "import-req", req, subject_name], capture_output=True)
        if p.returncode != 0:
            print(p.stderr)
        # p.check_returncode()

        cmd = f"./easyrsa sign-req {cert_type} {subject_name}"
        signer = pexpect.spawn(cmd)

        signer.expect("Confirm request details: ")
        signer.sendline("yes")

        # Parse the output to get the certificate file path
        lines = [line.decode("utf-8").strip() for line in signer]
        try:
            cert_created = list(filter(lambda x: x.find("Certificate created") != -1, lines))[0]
        except IndexError as e:
            print(lines)
            raise e

        cert_path = cert_created.replace("Certificate created at: ", "")
        return cert_path

    def sign_csr(self, csr_filename: str, contents: bytes) -> str:
        """ Given CSR file name and contents, sign it and return certificate file
        """
        os.chdir(self.ca_dir)
        # Save the file to the csr directory
        req_file_path = os.path.join(self.csr_dir, csr_filename)
        with open(req_file_path, "wb") as f:
            f.write(contents)
        # Sign it
        cert_name = remove_path_and_extension(csr_filename)
        return self._sign_csr(cert_name)

    def create_certificate(self, name: str, cert_type="server") -> str:
        """ Given a name create a certificate signed by the CA.
            Return the certificate path.
        """
        # Change dir
        os.chdir(self.ca_dir)

        req = os.path.join(self.csr_dir, f"{name}.req")
        # if it doesn't exist
        if not os.path.isfile(req):
            # Generate certificate request
            subject = f"/C=UK/ST=Greater London/L=London/O=nChain/OU=Research/CN={name}"
            self._create_csr(name, subject)

        # Import and sign certificate request
        return self._sign_csr(name, cert_type)

    def create_cert(self, subject: str, keyfile: str, certfile: str, cert_type: str) -> None:
        """ Given subject, keyfile and certifile
            Create the certs required for HTTPS web_interface and OCSP responder
        """
        # Create certificate
        created_certfile = self.create_certificate(subject, cert_type)
        # Copy cert (if required)
        if os.path.abspath(created_certfile) != os.path.abspath(certfile):
            copyfile(os.path.abspath(created_certfile), os.path.abspath(certfile))

        # Copy keyfile (if required)
        keyfile = os.path.join(self.csr_dir, subject + ".key")
        if os.path.abspath(keyfile) != os.path.abspath(keyfile):
            copyfile(os.path.abspath(keyfile), os.path.abspath(keyfile))

    def revoke_certificate(self, name: str) -> List[str]:
        """ Given a name revoke a certificate

            cd easy-rsa
            ./easyrsa revoke my-server
        """
        # Change dir
        os.chdir(self.ca_dir)

        cmd = f"./easyrsa revoke {name}"
        revoker = pexpect.spawn(cmd)

        revoker.expect("Continue with revocation:")
        revoker.sendline("yes")

        # Parse the output
        lines = [line.decode("utf-8").strip() for line in revoker]
        retval = list(filter(lambda x: x.find("Revoking Certificate") != -1, lines))[0]
        print(f"retval = {retval}")
        return retval

    def revoke_certificate_file(self, file: UploadFile) -> List[str]:
        """ given a certificate file revoke it
        """
        # Quick and dirty just use the cert name...
        cert_name = remove_path_and_extension(file.filename)

        return self.revoke_certificate(cert_name)

    def get_issued_certificates(self) -> List[str]:
        """ Return a list of issued certificates.
        """
        return os.listdir(self.issued_dir)

    def certificate_exists(self, name: str) -> bool:
        """ Return true if certificate exists.
        """
        return name + '.crt' in self.get_issued_certificates()

    def get_certificate_logs(self) -> List[str]:
        """ Return a list of certificates and their statuses
        """
        return load_file(self.log_file)

    def get_cert_file(self, name: str) -> Optional[FileResponse]:
        """ Return a FileResponse which haas the certificate associated with name
        """
        if self.certificate_exists(name):
            fname = name + ".crt"
            path = os.path.join(self.issued_dir, fname)
            return FileResponse(path=path, filename=fname, media_type="text")
        else:
            print(f"Certificate not found {name}")
            return None

    def _key_exists(self, name: str) -> bool:
        """ Return true if key exists.
        """
        return name + '.key' in os.listdir(self.csr_dir)

    def get_key_file(self, name: str) -> Optional[FileResponse]:
        """ Return the Key file associated with name
        """
        if self._key_exists(name):
            fname = name + ".key"
            path = os.path.join(self.csr_dir, fname)
            return FileResponse(path=path, filename=fname, media_type="text")
        else:
            print(f"Key file not found {name}")
            return None

    def get_ca_cert(self) -> FileResponse:
        """ Return the CA's certiicate for OCSP etc.
        """
        ca_cert_filename = os.path.basename(self.ca_cert)
        return FileResponse(path=self.ca_cert, filename=ca_cert_filename, media_type="text")

    def get_certificate_status(self, serial_number: str) -> Tuple[OCSPCertStatus, Optional[datetime.datetime], Optional[ReasonFlags]]:
        """ This should probably not be CA functionality but will put it here for now
        """
        # check log file log_file
        revocation_time = None
        revocation_reason = None
        index = load_file(self.log_file)
        results = list(filter(lambda x: serial_number in x, index))
        if len(results) != 1:
            return (OCSPCertStatus.UNKNOWN, revocation_time, revocation_reason)
        else:
            results = results[0].split()
            print(f"results = {results}")
            if results[0] == "R":
                revocation_reason = ReasonFlags.unspecified
                revocation_time = datetime.datetime.now()
                return (OCSPCertStatus.REVOKED, revocation_time, revocation_reason)

            else:
                return (OCSPCertStatus.GOOD, revocation_time, revocation_reason)

    def get_cert_from_name(self, cert_name: str) -> Optional[Certificate]:
        """ Return the certificate associated with name
        """
        if self.certificate_exists(cert_name):
            fname = cert_name + ".crt"
            path = os.path.join(self.issued_dir, fname)
            return load_cert_pem_file(path)
        else:
            print(f"Certificate not found {cert_name}")
            return None

    def get_cert_from_serial_number(self, serial_number: str) -> Optional[Certificate]:
        """ Given a serial_number return the associated Certificate
        """
        fname = os.path.join(self.certs_by_serial_no, serial_number + ".pem")
        cert = load_cert_pem_file(fname)
        if cert is None:
            # Try the revoked certs - here they are .crt for some reason
            # print(f'Loading fro the revoked certificate directory')
            fname = os.path.join(self.revoked_certs_by_serial_no, serial_number + ".crt")
            cert = load_cert_pem_file(fname)

        return cert

    def get_list_of_valid_serial_numbers(self) -> List[Tuple[int, str]]:
        """ Return a list of valid certificate serial numbers & subjects from
            the CA index file
        """
        valid_serial_numbers = []

        index = load_file(self.log_file)
        for lines in index:
            results = lines.split()
            if results[0] == 'V':
                # print(f'{results[4]}')
                valid_serial_numbers.append((int(results[2], base=16), "".join(results[4:])))

        return valid_serial_numbers

    def get_list_of_revoked_serial_numbers(self) -> List[Tuple[int, str]]:
        """ Return a list of revoked certificate serial numbers & subjects from
            the CA Index file
        """
        revoked_serial_numbers = []

        index = load_file(self.log_file)
        for lines in index:
            results = lines.split()
            if results[0] == 'R':
                revoked_serial_numbers.append((int(results[3], base=16), "".join(results[5:])))

        return revoked_serial_numbers


certificate_authority = CertificateAuthority()
