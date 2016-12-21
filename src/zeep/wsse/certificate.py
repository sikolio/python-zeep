import base64
import hashlib
import os
from uuid import uuid4


from lxml.builder import ElementMaker
from lxml import etree


from zeep.wsse import utils

import xmlsec
from OpenSSL import crypto


NSMAP = {
    'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
    'wsu': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
}
WSSE = ElementMaker(namespace=NSMAP['wsse'])
WSU = ElementMaker(namespace=NSMAP['wsu'])


def ns(namespace, tagname):
    return '{%s}%s' % (namespace, tagname)

class CertificateSigner(object):
    """CertificateSigner Profile 1.1

    """
    wssns = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0'    # noqa
    wssens = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
    wsuns = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'

    def __init__(self, keyfile, cert_file, their_cert):
        self.cert_file = cert_file
        self.keyfile = keyfile
        self.their_cert = their_cert

    def load_certfile(self):
        with file(self.cert_file, 'rb') as keyfile:
            self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, keyfile.read())

    def sign(self, envelope, headers):
        print(etree.tostring(envelope, pretty_print=True))

        signature = xmlsec.template.create(
            envelope,
            xmlsec.Transform.EXCL_C14N,
            xmlsec.Transform.RSA_SHA1,
        )

        key_info = xmlsec.template.ensure_key_info(signature)
        x509_data = xmlsec.template.add_x509_data(key_info)
        x509_issuer_serial = etree.Element('{ns}X509IssuerSerial')
        x509_data.append(x509_issuer_serial)
        x509_certificate = etree.Element('{ns}X509Certificate')
        x509_data.append(x509_certificate)

        key = xmlsec.Key.from_file(self.keyfile, xmlsec.KeyFormat.PEM)
        key.load_cert_from_file(self.cert_file, xmlsec.KeyFormat.PEM)

        security = utils.get_security_header(envelope)
        security.insert(0, signature)

        ctx = xmlsec.SignatureContext()
        ctx.key = key
        self._sign_node(ctx, signature, envelope.find('{http://schemas.xmlsoap.org/soap/envelope/}Body'))
        ctx.sign(signature)

        sec_token_ref = etree.SubElement(
            key_info, '{}SecurityTokenReference'.format(self.wssens)
        )
        sec_token_ref.append(x509_data)

        return envelope, headers

    def verify(self, envelope):
        pass

    def get_unique_id(self):
        return 'id-{0}'.format(uuid4())

    def ensure_id(self, node):
        """Ensure given node has a wsu:Id attribute; add unique one if not.

        Return found/created attribute value.

        """
        ID_ATTR = ns(self.wsuns, 'Id')
        id_val = node.get(ID_ATTR)
        if not id_val:
            id_val = self.get_unique_id()
            node.set(ID_ATTR, id_val)
        return id_val

    def _sign_node(self, ctx, signature, target):
        node_id = self.ensure_id(target)
        ref = xmlsec.template.add_reference(
            signature, xmlsec.Transform.SHA1, uri= '#' + node_id
        )
        xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)
        ctx.register_id(target, 'Id', self.wsuns)
