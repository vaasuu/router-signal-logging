#!/usr/bin/python3

""" log signal information from Huawei router  """
import xml.etree.ElementTree as ET
import xmltodict        # pip install xmltodict
import sys
import uuid
import hashlib
import hmac
from time import sleep
from binascii import hexlify
import requests
from config import ROUTER, USER, PASSWORD, LOGFILE
import datetime
import csv
import os.path

def generate_nonce():
    """ generate random clientside nonce """
    return uuid.uuid4().hex + uuid.uuid4().hex


def setup_session(client, server):
    """ gets the url from the server ignoring the respone, just to get session cookie set up """
    url = "http://%s/" % server
    response = client.get(url)
    response.raise_for_status()
    # will have to debug this one as without delay here it was throwing a buffering exception on one of the machines
    sleep(1)


def get_server_token(client, server):
    """ retrieves server token """
    url = "http://%s/api/webserver/token" % server
    token_response = client.get(url).text
    root = ET.fromstring(token_response)

    return root.findall('./token')[0].text


def get_client_proof(clientnonce, servernonce, password, salt, iterations):
    """ calculates server client proof (part of the SCRAM algorithm) """
    msg = "%s,%s,%s" % (clientnonce, servernonce, servernonce)
    salted_pass = hashlib.pbkdf2_hmac(
        'sha256', password, bytearray.fromhex(salt), iterations)
    client_key = hmac.new(b'Client Key', msg=salted_pass,
                          digestmod=hashlib.sha256)
    stored_key = hashlib.sha256()
    stored_key.update(client_key.digest())
    signature = hmac.new(msg.encode('utf_8'),
                         msg=stored_key.digest(), digestmod=hashlib.sha256)
    client_key_digest = client_key.digest()
    signature_digest = signature.digest()
    client_proof = bytearray()
    i = 0
    while i < client_key.digest_size:
        client_proof.append(client_key_digest[i] ^ signature_digest[i])
        i = i + 1

    return hexlify(client_proof)


def login(client, server, user, password):
    """ logs in to the router using SCRAM method of authentication """
    setup_session(client, server)
    token = get_server_token(client, server)
    url = "http://%s/api/user/challenge_login" % server
    request = ET.Element('request')
    username = ET.SubElement(request, 'username')
    username.text = user
    clientnonce = generate_nonce()
    firstnonce = ET.SubElement(request, 'firstnonce')
    firstnonce.text = clientnonce
    mode = ET.SubElement(request, 'mode')
    mode.text = '1'
    headers = {'Content-type': 'text/html',
               '__RequestVerificationToken': token[32:]}
    response = client.post(url, data=ET.tostring(
        request, encoding='utf8', method='xml'), headers=headers)
    scram_data = ET.fromstring(response.text)
    servernonce = scram_data.findall('./servernonce')[0].text
    salt = scram_data.findall('./salt')[0].text
    iterations = int(scram_data.findall('./iterations')[0].text)
    verification_token = response.headers['__RequestVerificationToken']
    login_request = ET.Element('request')
    clientproof = ET.SubElement(login_request, 'clientproof')
    clientproof.text = get_client_proof(
        clientnonce, servernonce, password, salt, iterations).decode('UTF-8')
    finalnonce = ET.SubElement(login_request, 'finalnonce')
    finalnonce.text = servernonce
    headers = {'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
               '__RequestVerificationToken': verification_token}

    url = "http://%s/api/user/authentication_login" % server
    result = client.post(url, data=ET.tostring(
        login_request, encoding='utf8', method='xml'), headers=headers)
    verification_token = result.headers['__RequestVerificationTokenone']
    #print("Headers: ", result.headers)
    print("Login successful…")
    return verification_token








def get_signal(client, server, token):
    """ gets router signal info via API """
    url = "http://%s/api/device/signal" % server
    headers = {'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
               '__RequestVerificationToken': token}
    resp=client.get(
        url,
        headers=headers)
    print("Got signal file")
    return resp

def remove_units_from_signalXML(client, ROUTER, token):
    resp = get_signal(client, ROUTER, token)
    xmltext = resp.text
    xmltext = xmltext.replace("dBm", "")
    xmltext = xmltext.replace("dB", "")
    xmltext = xmltext.replace("MHz", "")
    xmltext = xmltext.replace("kHz", "")
    xmltext = xmltext.replace("&gt;=", "") # the ">="
    return xmltext

def signal_xml_to_dict(client, ROUTER, token):
    xmltext = remove_units_from_signalXML(client, ROUTER, token)
    mydict = xmltodict.parse(xmltext)
    return mydict





client = requests.Session()
token = login(client, ROUTER, USER, PASSWORD)





def refresh_session():
    global token
    url = "http://%s/api/device/signal" % ROUTER
    r = client.get(url)

    if "error" in r.text:
        print("Session expired…")

        token = login(client, ROUTER, USER, PASSWORD)
        mydict = signal_xml_to_dict(client, ROUTER, token)

    else:
        mydict = signal_xml_to_dict(client, ROUTER, token)

    return mydict





# def print_mydict(mydict):
#     date = datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"
#     pci = mydict['response']['pci']
#     sc = mydict['response']['sc']
#     cell_id = mydict['response']['cell_id']
#     rsrq = mydict['response']['rsrq']
#     rsrp = mydict['response']['rsrp']
#     rssi = mydict['response']['rssi']
#     sinr = mydict['response']['sinr']
#     rscp = mydict['response']['rscp']
#     ecio = mydict['response']['ecio']
#     mode = mydict['response']['mode']
#     ulbandwidth = mydict['response']['ulbandwidth']
#     dlbandwidth = mydict['response']['dlbandwidth']
#     txpower = mydict['response']['txpower']
#     tdd = mydict['response']['tdd']
#     ul_mcs = mydict['response']['ul_mcs']
#     dl_mcs = mydict['response']['dl_mcs']
#     earfcn = mydict['response']['earfcn']
#     rrc_status = mydict['response']['rrc_status']
#     rac = mydict['response']['rac']
#     lac = mydict['response']['lac']
#     tac = mydict['response']['tac']
#     band = mydict['response']['band']
#     nei_cellid = mydict['response']['nei_cellid']
#     plmn = mydict['response']['plmn']
#     ims = mydict['response']['ims']
#     wdlfreq = mydict['response']['wdlfreq']
#     lteulfreq = mydict['response']['lteulfreq']
#     ltedlfreq = mydict['response']['ltedlfreq']
#     transmode = mydict['response']['transmode']
#     enodeb_id = mydict['response']['enodeb_id']
#     cqi0 = mydict['response']['cqi0']
#     cqi1 = mydict['response']['cqi1']
#     ulfrequency = mydict['response']['ulfrequency']
#     dlfrequency = mydict['response']['dlfrequency']
#     arfcn = mydict['response']['arfcn']
#     bsic = mydict['response']['bsic']
#     rxlev = mydict['response']['rxlev']

#     # Make list with the csv field data
#     entry = [date, pci, sc, cell_id, rsrq, rsrp, rssi, sinr, rscp, ecio, mode, ulbandwidth, dlbandwidth, txpower, tdd, ul_mcs, dl_mcs, earfcn, rrc_status, rac, lac, tac, band, nei_cellid, plmn, ims, wdlfreq, lteulfreq, ltedlfreq, transmode, enodeb_id, cqi0, cqi1, ulfrequency, dlfrequency, arfcn, bsic, rxlev]

#     return entry






for i in range(30):

    mydict = refresh_session()
    if not mydict.get('response'):
        print('Error retrieving key: response')
    else:
        dictresponse = mydict['response']

        # add date to dict
        date = datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"
        dictresponse['date'] = date

        # Check if logfile exists; if not, create new logfile and add header.
        filename = LOGFILE
        #https://stackoverflow.com/a/28325689

        file_exists = os.path.isfile(filename)

        with open (filename, 'a') as csvfile:
            headers = ['date', 'pci', 'sc', 'cell_id', 'rsrq', 'rsrp', 'rssi', 'sinr', 'rscp', 'ecio', 'mode', 'ulbandwidth', 'dlbandwidth', 'txpower', 'tdd', 'ul_mcs', 'dl_mcs', 'earfcn', 'rrc_status', 'rac', 'lac', 'tac', 'band', 'nei_cellid', 'plmn', 'ims', 'wdlfreq', 'lteulfreq', 'ltedlfreq', 'transmode', 'enodeb_id', 'cqi0', 'cqi1', 'ulfrequency', 'dlfrequency', 'arfcn', 'bsic', 'rxlev']
            writer = csv.DictWriter(csvfile, delimiter=',', lineterminator='\n',fieldnames=headers)

            if not file_exists:
                writer.writeheader()  # file doesn't exist yet, write a header
                print("Creating logfile", LOGFILE)
            writer.writerow(dictresponse)

    sleep(10)

