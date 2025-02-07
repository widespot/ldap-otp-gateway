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


def check_response(xml_str):
    xml = minidom.parseString(normalize(xml_str))
    if len(xml.childNodes) != 1:
        raise Exception(f'Expected root size to be 1 but got {len(xml.childNodes)} instead. XML was "{xml.toxml()}"')

    envelope_name = 'SOAP-ENV:Envelope'
    if xml.childNodes[0].nodeName != envelope_name:
        raise Exception(f'Expected root child node name to be "{envelope_name}" but got "{xml.childNodes[0].nodeName}" instead. XML was "{xml.toxml()}"')

    envelope = xml.childNodes[0]

    if len(envelope.childNodes) != 1:
        raise Exception(f'Expected envelope size to be 1 but got {len(envelope.childNodes)} instead. Envelope was "{envelope.toxml()}"')

    body_name = 'SOAP-ENV:Body'
    if envelope.childNodes[0].nodeName != body_name:
        raise Exception(f'Expected envelope child node name to be "{body_name}" but got "{envelope.childNodes[0].nodeName}" instead. Envelope was "{envelope.toxml()}"')

    body = envelope.childNodes[0]

    if len(body.childNodes) != 1:
        raise Exception(f'Expected body size to be 1 but got {len(body.childNodes)} instead. Body was "{body.toxml()}"')

    response_name = 'ns1:openotpSimpleLoginResponse'
    if body.childNodes[0].nodeName != response_name:
        raise Exception(f'Expected body child node name to be "{response_name}" but got "{body.childNodes[0].nodeName}" instead. Body was "{body.toxml()}"')

    response = body.childNodes[0]
    if len(response.childNodes) != 5:
        raise Exception(f'Expected response size to be 5 but got {len(body.childNodes)} instead. Response was "{response.toxml()}')

    code = response.childNodes[0]
    if len(code.childNodes) != 1:
        raise Exception(f'Expected response code size to be 1. Response was "{response.toxml()}')
    if code.childNodes[0].nodeType != code.childNodes[0].TEXT_NODE:
        raise Exception(f'Expected response code type to be textual. Response was "{response.toxml()}')
    if code.childNodes[0].data != '1':
        raise Exception(f'Expected response code to be "1" but got {code.childNodes[0].data} instead. Response was "{response.toxml()}')

    return True, None


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
        logging.debug(f"OtpBackend() uri={self.uri}")

    def verify(self, username, password, otp) -> (bool, (str or None)):
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

        logging.error(f"RCDevs OTP Backend verify() Request data={data}".replace(
            "{password}{otp}",
            f"{'*'*len(password)}{'*'*len(otp)}"
        ))

        r = requests.post(
            self.uri,
            headers={"Content-Type": "text/xml"},
            data=data)

        response_txt = r.text
        logging.debug(f"RCDevs OTP Backend verify() Response: {response_txt}")

        r.raise_for_status()

        try:
            check_response(response_txt)
        except Exception as e:
            return False, f'RCDevs OTP Backend replied: {e}'

        return True, None
