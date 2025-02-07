import logging
import os

import requests

from .base_otp_backend import BaseOtpBackend

from xml.dom import minidom
from xml.dom.minidom import Node


OTP_PROTOCOL = os.getenv('OTP_PROTOCOL', 'http')
OTP_HOST = os.getenv('OTP_HOST', 'localhost')
OTP_PORT = os.getenv('OTP_PORT', '8080')
OTP_ENDPOINT = os.getenv('OTP_ENDPOINT', 'openotp/')


def remove_blanks(node):
    for x in node.childNodes:
        if x.nodeType == Node.TEXT_NODE:
            if x.nodeValue:
                x.nodeValue = x.nodeValue.strip()
        elif x.nodeType == Node.ELEMENT_NODE:
            remove_blanks(x)


def normalize(xml_str) -> str:
    xml = minidom.parseString(xml_str)
    remove_blanks(xml)
    xml.normalize()
    return xml.toxml()


def is_success(xml_str):
    xml = minidom.parseString(xml_str)
    if len(xml.childNodes) != 1:
        logging.warning('Unexpected root size: ' + str(len(xml.childNodes)))
        return False

    if xml.childNodes[0].nodeName != 'SOAP-ENV:Envelope':
        logging.warning('Unexpected first level child node name: ' + str(xml.childNodes[0].nodeName))
        return False

    envelope = xml.childNodes[0]

    if len(envelope.childNodes) != 1:
        logging.warning('Unexpected envelope size: ' + str(len(envelope.childNodes)))
        return False

    if envelope.childNodes[0].nodeName != 'SOAP-ENV:Body':
        logging.warning('Unexpected envelope first child node name: ' + str(envelope.childNodes[0].nodeName))
        return False

    body = envelope.childNodes[0]

    if len(body.childNodes) != 1:
        logging.warning('Unexpected body size: ' + str(len(body.childNodes)))
        return False

    if body.childNodes[0].nodeName != 'ns1:openotpSimpleLoginResponse':
        return False

    response = body.childNodes[0]
    if len(response.childNodes) != 5:
        return False

    code = response.childNodes[0]

    if len(code.childNodes) != 1:
        return False
    if code.childNodes[0].nodeType != code.childNodes[0].TEXT_NODE:
        return False
    if code.childNodes[0].data != '1':
        return False

    return True


SUCCESS_RESPONSE_TXT = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="urn:openotp">
<SOAP-ENV:Body>
<ns1:openotpSimpleLoginResponse>
<code>1</code>
<error/>
<message>Authentication success</message>
<data/>
<concat>8</concat>
</ns1:openotpSimpleLoginResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
"""
SUCCESS_RESPONSE_NORM_TXT = normalize(SUCCESS_RESPONSE_TXT)


class OtpBackend(BaseOtpBackend):
    """
    Example success response:
    ```
    <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="urn:openotp">
    <SOAP-ENV:Body>
    <ns1:openotpSimpleLoginResponse>
        <code>1</code>
        <error/>
        <message>Authentication success</message>
        <data/>
        <concat>8</concat>
    </ns1:openotpSimpleLoginResponse>
    </SOAP-ENV:Body>
    </SOAP-ENV:Envelope>
    ```
    """
    def __init__(self):
        self.uri = f"{OTP_PROTOCOL}://{OTP_HOST}:{OTP_PORT}/{OTP_ENDPOINT}"
        logging.debug(f"uri={self.uri}")

    def verify(self, username, password, otp) -> bool:
        logging.debug(f"uri={self.uri}")
        data = (
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/1999/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/1999/XMLSchema\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
            "<SOAP-ENV:Header/>"
            "<SOAP-ENV:Body>"
            "<m:openotpSimpleLogin xmlns:m=\"urn:openotp\">"
            f"<m:username xsi:type=\"xsd:string\">{username}</m:username>"
            "<m:domain xsi:type=\"xsd:string\"/>"
            f"<m:anyPassword xsi:type=\"xsd:string\">{password}{otp}</m:anyPassword>"
            "<m:client xsi:type=\"xsd:string\">ldapsearch</m:client>"
            "<m:source xsi:type=\"xsd:string\"/>"
            "<m:settings xsi:type=\"xsd:string\">ChallengeMode=No</m:settings>"
            "<m:options xsi:type=\"xsd:string\">NOVOICE,-U2F,LDAPDN</m:options>"
            "<m:context xsi:type=\"xsd:string\"/><m:retryId xsi:type=\"xsd:string\"/>"
            "</m:openotpSimpleLogin>"
            "</SOAP-ENV:Body>"
            "</SOAP-ENV:Envelope>")
        logging.debug(f"data={data}")

        r = requests.post(
            self.uri,
            headers={"Content-Type": "text/xml"},
            data=data)

        response_txt = r.text
        logging.debug(f"RCDevs OTP Backend verify() Response: {response_txt}")

        r.raise_for_status()

        return is_success(response_txt)
