#!/usr/bin/env python
from subprocess import Popen, PIPE
from re import search

class CertificateManager:

    MACHINE_TRUST='-m Trust'
    USER_TRUST='Trust'
    MACHINE_MY='-m My'
    USER_MY='My'
    CERT='-c'
    CRL='-crl'
    CTL='-ctl'

    def __init__(self):
        pass

    def list_certs(self, object_type=CERT, store=USER_TRUST):
        cmd = ('certmgr -list %s %s' % (object_type, store))
        p = Popen(cmd.split(), stdout=PIPE, stderr=PIPE)
        o, e = p.communicate()
        if p.returncode:
            raise CertMgrException('Did not find any certificates.')
        clist = [a for a in o.split('\n\n') if not (a.startswith('Mono') or 
            a == '')]
        certs = []
        for c in clist:
            fields = {}
            for line in c.splitlines():
                if ':' in line:
                    item = line.split(':', 1)
                    fields[item[0].strip()] = item[1].strip()
            certs.append(MonoCertificate(fields['Serial Number'], 
                fields['Issuer Name'], fields['Subject Name'], 
                fields['Valid From'], fields['Valid Until'], 
                fields['Unique Hash'], object_type, store))
        return certs

    def delete_all(self):
        for obj_type in (CERT, CRL, CTL):
            for store in (MACHINE_TRUST, USER_TRUST, MACHINE_MY, USER_MY):
                for c in self.list_certs(object_type=obj_type, store=store):
                    c.delete()
                
    def install_cer(self, cer_path, object_type=CERT, store=USER_MY):
        cmd = 'certmgr -add %s %s %s' % (object_type, store, cer_path)
        p = Popen(cmd.split(), stdout=PIPE, stderr=PIPE)
        o, e = p.communicate()
        if p.returncode:
            raise CertMgrException('Failed to install certificate. %s' % e)

    def install_p12(self, p12_path, object_type=CERT, store=USER_MY):
        cmd = 'certmgr -importKey %s %s %s' % (object_type, store, p12_path)
        p = Popen(cmd.split(), stdout=PIPE, stderr=PIPE)
        o, e = p.communicate()
        if p.returncode:
            raise CertMgrException('Failed to install P12. %s' % e)

class MonoCertificate:

    def __init__(self, serial, issuer_subject, subject, valid_from,
        valid_until, cert_hash, object_type=CertificateManager.CERT, 
        store=CertificateManager.USER_MY):
        self.__serial = serial
        self.__issuer_subject = issuer_subject
        self.__subject = subject
        self.__valid_from = valid_from
        self.__valid_until = valid_until
        self.__cert_hash = cert_hash
        self.__object_type = object_type
        self.__store = store

    def delete(self):
        cmd = 'certmgr -del %s %s %s' % (self.__object_type, self.__store, 
            self.__cert_hash)
        p = Popen(cmd.split(), stdout=PIPE, stderr=PIPE)
        o, e = p.communicate()
        if p.returncode:
            raise CertMgrException('Failed to delete certificate. %s' % e)

    def hash(self):
        return self.__cert_hash


class CertMgrException(Exception):
    pass

