#!/usr/bin/env python3
import argparse
import glob
import hashlib
import logging
import OpenSSL
import os
import random
import requests
import sys
import textwrap
import time
import yaml

from datetime import datetime

__author__ = 'Nicolas Ledez'
__copyright__ = 'Copyright 2017, Nicolas Ledez'
__credits__ = ['Nicolas Ledez']
__license__ = 'MIT'
__version__ = '1.0.0'
__maintainer__ = 'Nicolas Ledez'
__email__ = 'github.public@ledez.net'
__status__ = 'Production'

# Install logger part
LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

# Hardcoded acme-tiny repository
AT_GIT_URL = 'https://github.com/diafygi/acme-tiny.git'


class X509Parser():
    '''
    Module to parse certificate files
    '''
    def __init__(self, filename, validity_need=30, generate=False):
        self.filename = filename
        self.validity_need = validity_need
        self.generate = generate
        self.content = ''.join(open(self.filename).readlines())
        x509_cert = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM,
            self.content)
        self.subject = x509_cert.get_subject().get_components()[0][1]
        self.not_after = x509_cert.get_notAfter()
        self.update_validity_in_days()

    def __str__(self):
        return 'subject: {}, not_after: {}: validity_in_days: {}'.format(
            self.subject,
            self.not_after,
            self.validity_in_days)

    def update_validity_in_days(self):
        try:
            as_timestamp = time.strptime(str(self.not_after)[2:10], '%Y%m%d')
            validity_limit = datetime.fromtimestamp(time.mktime(as_timestamp))
            now = datetime.utcnow()
            LOGGER.debug(validity_limit)
            difference = validity_limit-now
            self.validity_in_days = difference.days
        except TypeError:
            LOGGER.info("Can't parse {}".format(self.filename))
            LOGGER.info(self.not_after)
            raise

    def check_validity(self):
        return self.validity_in_days < self.validity_need


class CertificateManager():
    def __init__(self, config_filename='/etc/acme-tiny/config.yaml',
                 dry_run=False, staging=False, show=False, validity_need=30,
                 generate=False):

        self.need_to_generate = []
        self.need_to_regenerate = []
        self.need_to_restart = []
        self.certificates = {}
        self.show = show
        self.validity_need = validity_need
        self.dry_run = dry_run
        self.staging = staging
        self.generate = generate

        self.load_config_file(config_filename)
        self.acme_tiny = ACMETiny(self.config['acme'],
                                  dry_run=self.dry_run,
                                  staging=self.staging)

        if self.dry_run:
            LOGGER.info('Run in dry mode')
        if self.show:
            LOGGER.info('Certificate(s) information:')

        self.load_certificates_config()
        self.parse_certificates()
        self.show_or_generate()
        self.show_or_regenerate()

    def load_config_file(self, config_filename):
        stream = open(config_filename)
        self.config = yaml.load(stream)
        self.services = self.config['services']
        self.acme = self.config['acme']

    def load_certificates_config(self):
        self.certificates_path = self.config.get('certificates',
                                                 {}).get('path')
        for certificate_path in glob.glob(self.certificates_path):
            stream = open(certificate_path)
            certificate = yaml.load(stream)
            for key in certificate.keys():
                self.certificates[key] = certificate[key]

    def parse_certificates(self):
        for cn in self.certificates:
            cert_path = self.acme['cert_path'].format(cn)
            if os.path.isfile(cert_path):
                cert_info = X509Parser(cert_path,
                                       validity_need=self.validity_need,
                                       generate=self.generate)
                if self.show:
                    LOGGER.info(cert_info)
                if cert_info.check_validity():
                    services_to_restart = self.certificates[cn]['restart']
                    self.need_to_regenerate.append(cn)
                    for service in services_to_restart:
                        if service not in self.need_to_restart:
                            self.need_to_restart.append(service)
            else:
                self.need_to_generate.append(cn)

    def show_or_generate(self):
        if self.show:
            if len(self.need_to_generate) > 0:
                LOGGER.info('\nNeed to generate certificate(s):')
                LOGGER.info('\n'.join(self.need_to_generate))
        else:
            for certificate in self.need_to_generate:
                self.bootstrap(certificate)

    def show_or_regenerate(self):
        if self.show:
            if len(self.need_to_regenerate) > 0:
                LOGGER.info('\nNeed to regenerate certificate(s):')
                LOGGER.info('\n'.join(self.need_to_regenerate))
                LOGGER.info('\nNeed to restart service(s) after regeneration:')
                LOGGER.info('\n'.join(self.need_to_restart))
        else:
            for certificate in self.need_to_regenerate:
                self.regenerate(certificate)

            for service in self.need_to_restart:
                self.restart(service)

    def restart(self, service):
        cmd = self.services[service]
        LOGGER.info('Launch: {}'.format(cmd))
        if not self.dry_run:
            os.system(cmd)

    def bootstrap(self, certificate):
        LOGGER.info('Generate {}'.format(certificate))
        key_filename = self.acme['priv_path'].format(certificate)
        csr_filename = self.acme['request_path'].format(certificate)
        crt_filename = self.acme['cert_path'].format(certificate)
        pem_filename = self.acme['chain_pem_path'].format(certificate)
        root_dir = os.path.dirname(key_filename)
        if not os.path.isdir(root_dir):
            LOGGER.info('Need to create {}'.format(root_dir))
            os.mkdir(root_dir, mode=0o750)
        if not os.path.isfile(key_filename):
            cmd = self.acme['cmd_priv_key'].format(key_filename)
            LOGGER.info(cmd)
            os.system(cmd)
        if not os.path.isfile(csr_filename):
            cmd = self.acme['cmd_csr'].format(key_filename, certificate,
                                              csr_filename)
            LOGGER.info(cmd)
            os.system(cmd)
        if not os.path.isfile(crt_filename):
            cmd = self.acme['cmd_self_sign'].format(csr_filename, crt_filename,
                                                    key_filename)
            LOGGER.info(cmd)
            os.system(cmd)
        if not os.path.isfile(pem_filename):
            cmd = self.acme['cmd_self_sign'].format(csr_filename, pem_filename,
                                                    key_filename)
            LOGGER.info(cmd)
            os.system(cmd)

    def regenerate(self, certificate):
        LOGGER.info('Regenerate {}'.format(certificate))
        self.acme_tiny.sign_certificate(certificate)


class ACMETiny():
    def __init__(self, config, dry_run=False, staging=False):
        self.config = config
        self.install_or_update()
        acme_path = self.config['tiny_path']
        if acme_path not in sys.path:
            sys.path.append(acme_path)
        import acme_tiny

        self.dry_run = dry_run
        self.staging = staging
        self.acme_tiny = acme_tiny
        self.check_ca()

        if self.dry_run or self.staging:
            LOGGER.info('!!!Use LE staging!!!')
            self.ca = 'https://acme-staging.api.letsencrypt.org'
        else:
            self.ca = acme_tiny.DEFAULT_CA

    def install_or_update(self):
        acme_path = self.config['tiny_path']
        if os.path.isdir(acme_path):
            cmd = 'cd {} ; git pull'.format(acme_path)
            LOGGER.debug(cmd)
            os.system(cmd)
        else:
            LOGGER.debug('Need to create {}'.format(acme_path))
            root_dir = os.path.dirname(acme_path)
            LOGGER.debug('Git clone in {}'.format(root_dir))
            cmd = 'cd {} ; git clone --depth 1 {}'.format(root_dir, AT_GIT_URL)
            LOGGER.debug(cmd)
            os.system(cmd)

        cron_path = self.config['cron_filename']
        if not os.path.isfile(cron_path):
            LOGGER.info('Need to create {}'.format(cron_path))
            cron = '{} {} * * *       root    '
            cron += '/usr/local/acme_helper/acme_helper.py '
            cron += '>> /var/log/acme_tiny.log 2>&1\n'
            cron = cron.format(
                random.randrange(0, 59),
                random.randrange(0, 23)
            )
            LOGGER.info(cron)
            with open(cron_path, 'w') as stream:
                stream.write(cron)

    def check_ca(self):
        existing_ca = False
        need_to_update_ca = False

        if os.path.isfile(self.config['intermediate_certs']):
            existing_ca = True
            fhash = hashlib.sha1()
            fhash.update(''.join(
                open(self.config['intermediate_certs']).readlines()).encode())
        else:
            LOGGER.info('Need to download')
            need_to_update_ca = True

        r = requests.get(self.config['intermediate_url'])
        intermediate_ca_content = r.text
        self.ca_content = intermediate_ca_content

        # Downloaded hash
        dhash = hashlib.sha1()
        dhash.update(intermediate_ca_content.encode())

        if existing_ca:
            size_match = fhash.digest_size == dhash.digest_size
            hex_match = fhash.hexdigest() == dhash.hexdigest()
            if size_match and hex_match:
                need_to_update_ca = False
            else:
                need_to_update_ca = True

        if need_to_update_ca:
            LOGGER.info('Update {}'.format(self.config['intermediate_certs']))
            if not self.dry_run:
                with open(self.config['intermediate_certs'], 'w') as stream:
                    stream.write(intermediate_ca_content)

    def sign_certificate(self, certificate):
        csr_filename = self.config['request_path'].format(certificate)
        crt_filename = self.config['cert_path'].format(certificate)
        chain_pem_filename = self.config['chain_pem_path'].format(certificate)
        signed_crt = self.acme_tiny.get_crt(self.config['key'],
                                            csr_filename,
                                            self.config['chalenge_path'],
                                            log=LOGGER,
                                            CA=self.ca)

        if not self.dry_run:
            with open(crt_filename, 'w') as stream:
                stream.write(signed_crt)
            with open(chain_pem_filename, 'w') as stream:
                stream.write(signed_crt+self.ca_content)


def main(argv):
    help_text = '''\
        This script automates the let's encrypt certificates with:
        https://github.com/diafygi/acme-tiny
    '''

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(help_text)
    )
    parser.add_argument('--quiet', action='store_const', const=logging.ERROR,
                        help='suppress output except for errors')
    parser.add_argument('--dry', action='store_const', const=True,
                        help='Launch in dry mode (in staging LE environnement)'
                        )
    parser.add_argument('--generate', action='store_const', const=True,
                        help='Generate missing certificate'
                        )
    parser.add_argument('--debug', action='store_const', const=True,
                        help='Launch in debug mode'
                        )
    parser.add_argument('--show', action='store_const', const=True,
                        help='Only show certificate informations'
                        )
    parser.add_argument('--staging', action='store_const', const=True,
                        help='Use LE staging (for tests)'
                        )
    parser.add_argument('--day', default=30,
                        help='Certificate validity days before regenerate them'
                        )

    args = parser.parse_args(argv)
    LOGGER.setLevel(args.quiet or args.debug or LOGGER.level)
    LOGGER.info('==== Started at {}'.format(datetime.utcnow()))
    CertificateManager(dry_run=args.dry, validity_need=int(args.day),
                       show=args.show, staging=args.staging,
                       generate=args.generate)
    LOGGER.info('==== Finished at {}'.format(datetime.utcnow()))


if __name__ == '__main__':  # pragma: no cover
    main(sys.argv[1:])
