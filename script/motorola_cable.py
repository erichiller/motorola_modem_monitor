""" Motorola Modem monitoring script

Supports Elasticsearch and InfluxDB

Usually run in powershell with:

    while ( $true ) { python .\motorola_cable.py ; sleep -Seconds 60 }

"""


from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import hmac
import time
import logging
import ssl

from typing import Union, Dict, List

import json

from pprint import pformat
import os
_LOGGER = logging.getLogger(__name__)


ON = 'ON'
OFF = 'OFF'

if "DEBUG" in os.environ and os.environ['DEBUG'].lower() == "true":
    _LOGGER.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    # create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # add formatter to ch
    ch.setFormatter(formatter)
    # add ch to logger
    _LOGGER.addHandler(ch)
    _LOGGER.debug("\nstarting...")



class MotorolaModem(object):
    """
    Class to access:
        * D-Link Smart Plug Switch W215
        * D-Link Smart Plug DSP-W110

    Usage example when used as library:
    p = SmartPlug("192.168.0.10", ('admin', '1234'))

    # change state of plug
    p.state = OFF
    p.state = ON

    # query and print current state of plug
    print(p.state)

    Note:
    The library is greatly inspired by the javascript library by @bikerp (https://github.com/bikerp).
    Class layout is inspired by @rkabadi (https://github.com/rkabadi) for the Edimax Smart plug.
    """

    def __init__(self, ip, password, user = "admin"):
        """
        Create a new SmartPlug instance identified by the given URL and password.

        :rtype : object
        :param host: The IP/hostname of the SmartPlug. E.g. '192.168.0.10'
        :param password: Password to authenticate with the plug. Located on the plug.
        :param user: Username for the plug. Default is admin.
        """
        _LOGGER.debug("MotorolaModem -> __init__()")
        self.ip = ip
        self.url = "https://{}:443/HNAP1/".format(ip)
        self.user = user
        self.password = password
        self.authenticated = None
        self._error_report = False
        self.sslContext = ssl.SSLContext()  # disable SSL cert verification
        self.getStatus()

    def getStatus(self):
        _LOGGER.debug("MotorolaModem -> getStatus()")
        self.status = self.Action(Action="GetMultipleHNAPs", responseElement="", params = "")

    def requestBody(self, Action, params):
        _LOGGER.debug("MotorolaModem -> requestBody()")
        """ Return the request payload for an action as json.

        :type Action: str
        :type params: str
        :param Action: Which action to perform
        :param params: Any parameters required for request
        :return json payload for request
        """
        return '''"{{}": {}}'''.format(Action, json.dumps(params) )


    def getDownstreamChannel(self):
        _LOGGER.debug("MotorolaModem -> getDownstreamChannel()")
        channelStatus = {}
        channels = self.status["GetMultipleHNAPsResponse"]["GetMotoStatusDownstreamChannelInfoResponse"]["MotoConnDownstreamChannel"].split("|+|")
        for channel in channels:
            channel_number, state, modulation, channel_id, mhz, power, snr, errors_corrected, errors_uncorrected, _ = channel.split("^")
            channelStatus[channel_number] = {
                "channel_number": int(channel_number),
                "state": state,
                "modulation": modulation,
                "channel_id": int(channel_id),
                "mhz": float(mhz),
                "power": float(power.strip()),
                "snr": float(snr),
                "errors_corrected": int(errors_corrected),
                "errors_uncorrected": int(errors_uncorrected)
            }
        return channelStatus

    def getUpstreamChannel(self
                           ) -> Dict[int, Dict[str, Union[float, int, str]]]:
        _LOGGER.debug("MotorolaModem -> getUpstreamChannel()")
        channelStatus = {}
        channels = self.status["GetMultipleHNAPsResponse"]["GetMotoStatusUpstreamChannelInfoResponse"]["MotoConnUpstreamChannel"].split("|+|")
        for channel in channels:
            channel_number, state, modulation, channel_id, rate, mhz, power, _ = channel.split("^")
            channelStatus[channel_number] = {
                "channel_number": int(channel_number),
                "state": state,
                "modulation": modulation,
                "channel_id": int(channel_id),
                "rate": int(rate),
                "mhz": float(mhz),
                "power": float(power.strip())
            }
        return channelStatus

    def getMotoStatusConnectionInfo(self):
        _LOGGER.debug("MotorolaModem -> getMotoStatusConnectionInfo()")
        return self.status["GetMultipleHNAPsResponse"]["GetMotoStatusConnectionInfoResponse"]

    def getUptime(self) -> float:
        _LOGGER.debug("MotorolaModem -> getUptime()")
        days, hms = self.getMotoStatusConnectionInfo()["MotoConnSystemUpTime"].split(" days ")

        # input( f":days:{days}")
        # input( f":hms:{hms}")

        hours, minutes, seconds = hms.split(":")
        delta_seconds = (
            ( int(days) * 24 * 60 * 60 ) +
            ( int(hours.strip("h")) * 60 * 60 ) +
            ( int(minutes.strip("m")) * 60 ) +
            ( int(seconds.strip("s")))
        )

        # input( f':m:{int(hours.strip("h"))}')
        # input( f':m:{int(minutes.strip("m"))}')
        # input( f':s:{int(seconds.strip("s"))}')
        # input( f':==:{int(delta_seconds)}')
        return float(delta_seconds)

    def getMotoStatusStartupSequence(self):
        _LOGGER.debug("MotorolaModem -> getMotoStatusStartupSequence()")
        return self.status["GetMultipleHNAPsResponse"]["GetMotoStatusStartupSequenceResponse"]


    def Action(self, Action, responseElement, params = "", recursive = False):
        """Generate the SOAP action call.

        action = "GetMultipleHNAPs"

        :type Action: str
        :type responseElement: str
        :type params: str
        :type recursive: bool
        :param Action: The action to perform on the device
        :param responseElement: The JSON element that is returned upon success
        :param params: Any additional parameters required for performing request (i.e. RadioID, moduleID, ect)
        :param recursive: True if first attempt failed and now attempting to re-authenticate prior
        :return: Text enclosed in responseElement brackets
        """
        _LOGGER.debug("MotorolaModem -> Action()")
        # Authenticate client
        if self.authenticated is None:
            self.authenticated = self.auth()
        auth = self.authenticated
        self.authenticated = None

        if auth is None:
            return None
        payload = """{"GetMultipleHNAPs":{"GetMotoStatusStartupSequence":"","GetMotoStatusConnectionInfo":"","GetMotoStatusDownstreamChannelInfo":"","GetMotoStatusUpstreamChannelInfo":"","GetMotoLagStatus":""}}"""

        # Timestamp in microseconds
        time_stamp = str(round(time.time() / 1e6))

        action_url = '"http://purenetworks.com/HNAP1/{}"'.format(Action)
        AUTHKey = hmac.new(
            auth[0].encode(), (time_stamp + action_url).encode(),
            digestmod='md5').hexdigest().upper() + " " + time_stamp

        headers = {'Content-Type' : '"application/json; charset=utf-8"',
                   'SOAPAction': '"http://purenetworks.com/HNAP1/{}"'.format(Action),
                   'HNAP_AUTH' : '{}'.format(AUTHKey),
                   'Cookie' : 'uid={}'.format(auth[1])}

        _LOGGER.debug("MotorolaModem -> Action() trying urlopen")
        try:
            response = urlopen(Request(self.url, payload.encode(), headers),
                               context=self.sslContext,
                               timeout=60)
            _LOGGER.debug(f"MotorolaModem -> Action() received {pformat(response)}")
            # pprint(response)
        except (HTTPError, URLError) as err:
            _LOGGER.error(
                f"MotorolaModem -> Action() ERROR accessing URL {self.ip} :\n\t{err}"
            )
            # Try to re-authenticate once
            self.authenticated = None
            # Recursive call to retry action
            if not recursive:
                _LOGGER.warning(
                    "MotorolaModem -> Action() trying again, recursive marked True"
                )
                return_value = self.Action(Action, responseElement, params, True)
            if recursive or return_value is None:
                _LOGGER.error("Failed to open url to {}".format(self.ip))
                self._error_report = True
                return None
            else:
                return return_value

        _LOGGER.debug("MotorolaModem -> Action() reading response date")
        xmlData = response.read().decode()

        _LOGGER.debug("MotorolaModem -> Action() returning xmlData as JSON")
        return json.loads(xmlData)


    def auth(self):
        """Authenticate using the SOAP interface.

        Authentication is a two-step process. First a initial payload
        is sent to the device requesting additional login information in the form
        of a publickey, a challenge string and a cookie.
        These values are then hashed by a MD5 algorithm producing a privatekey
        used for the header and a hashed password for the XML payload.

        If everything is accepted the XML returned will contain a LoginResult tag with the
        string 'success'.

        See https://github.com/bikerp/dsp-w215-hnap/wiki/Authentication-process for more information.
        """
        _LOGGER.debug("MotorolaModem -> auth()")
        payload = self.initial_auth_payload()

        # Build initial header
        headers = {
            'Content-Type' : '"application/json; charset=utf-8"',
            'SOAPAction': '"http://purenetworks.com/HNAP1/Login"' }

        # Request privatekey, cookie and challenge
        try:
            response = urlopen(Request(self.url, payload, headers),
                               context=self.sslContext)
        except URLError as err:
            if self._error_report is False:
                _LOGGER.warning('(auth) Unable to open a connection to host {} at {}\n\tERROR: {}'.format(self.ip, self.url, err))
                self._error_report = True
            return None
        except HTTPError as http_err:
            if self._error_report is False:
                _LOGGER.warning(
                    '(auth) Unable to open a connection to host {} at {}\n\tHTTP ERROR: {}'
                    .format(self.ip, self.url, http_err))
                self._error_report = True
            return None
        except Exception as err:
            if self._error_report is False:
                _LOGGER.warning(
                    '(auth) Unable to open a connection to host {} at {}\n\tOther error occurred: {}'
                    .format(self.ip, self.url, err))
                self._error_report = True
                return None
        print('Successfully connected to host {} at {}'.format(
                self.ip, self.url))
        json_response = json.loads(response.read().decode())["LoginResponse"]
        # Find responses
        ChallengeResponse = json_response["Challenge"]
        CookieResponse = json_response["Cookie"]
        PublickeyResponse = json_response["PublicKey"]

        if (ChallengeResponse is None or CookieResponse is None or PublickeyResponse is None) and self._error_report is False:
            _LOGGER.warning("Failed to receive initial authentication from device.")
            self._error_report = True
            return None

        if self._error_report is True:
            return None

        Challenge = ChallengeResponse
        Cookie = CookieResponse
        Publickey = PublickeyResponse

        # Generate hash responses
        PrivateKey = hmac.new((Publickey + self.password).encode(),
                              (Challenge).encode(),
                              digestmod='md5').hexdigest().upper()
        login_pwd = hmac.new(PrivateKey.encode(),
                             Challenge.encode(),
                             digestmod='md5').hexdigest().upper()

        _LOGGER.debug("MotorolaModem -> auth() calling auth_payload")
        response_payload = self.auth_payload(login_pwd)
        _LOGGER.debug("MotorolaModem -> auth() returned from auth_payload")
        # Build response to initial request
        headers = {
            'Content-Type' : '"application/json; charset=utf-8"',
            'SOAPAction': '"http://purenetworks.com/HNAP1/Login"',
            'HNAP_AUTH' : '"{}"'.format(PrivateKey),
            'Cookie' : 'uid={}'.format(Cookie)}
        response = urlopen(Request(self.url, response_payload, headers),
                           context=self.sslContext)
        resp = json.loads(response.read().decode())["LoginResponse"]

        # Find responses
        login_status = resp["LoginResult"].lower()

        if login_status not in ( "ok" , "success" ) and self._error_report is False:
            _LOGGER.error("Failed to authenticate with host {}".format(self.ip))
            self._error_report = True
            return None

        self._error_report = False  # Reset error logging
        _LOGGER.debug("MotorolaModem -> auth() returing")
        return (PrivateKey, Cookie)

    def initial_auth_payload(self):
        """Return the initial authentication payload."""
        _LOGGER.debug("MotorolaModem -> initial_auth_payload()")
        # return ''''''.format(self.user)
        return bytes(json.dumps(
            {"Login": {
                "Action": "request",
                "Username": self.user,
                "LoginPassword": "",
                "Captcha": "",
                "PrivateLogin": "LoginPassword"
            }}), 'utf-8')

    def auth_payload(self, login_pwd):
        """ Generate a new payload containing generated hash information.

        :type login_pwd: str
        :param login_pwd: hashed password generated by the auth function.
        """
        _LOGGER.debug("MotorolaModem -> auth_payload()")
        return bytes(json.dumps(
            {"Login": {
                "Action": "request",
                "Username": self.user,
                "LoginPassword": login_pwd,
                "Captcha": "",
                "PrivateLogin": "LoginPassword"
            }}), 'utf-8')




modem = MotorolaModem("192.168.100.1", "nq3uy1q5gm", "ehiller")
# pprint(modem.getDownstreamChannel())
# pprint(modem.getUpstreamChannel())
# pprint(modem.getMotoStatusConnectionInfo())
# pprint(modem.getMotoStatusStartupSequence())
# pprint(modem.getUptime())


import http

from influxdb import InfluxDBClient


class InfluxDBHandler:
    """ Push to InfluxDB

    Reference
    =========
    https://influxdb-python.readthedocs.io/en/latest/

    https://www.influxdata.com/blog/getting-started-python-influxdb/

    InfluxDBClient : https://influxdb-python.readthedocs.io/en/latest/api-documentation.html#influxdbclient

    """

    client: InfluxDBClient

    def __init__(self, host, port=8086, database="cable_modem"):
        _LOGGER.debug("InfluxDBHandler -> __init__()")
        self.client = InfluxDBClient(host=host, port=port)
        if database not in [db["name"] for db in self.client.get_list_database()]:
            self.client.create_database(database)
        self.client.switch_database(database)

    def send(self, data):
        _LOGGER.debug("InfluxDBHandler -> send()")
        self.client.write_points(data)



class ElasticHandler:
    """ ElasticHandler is specialized to log to ElasticSearch """

    def __init__(self, host, index_name: str = "", secure: bool = False, credentials = None, context = None):
        """ Initialize the instance with the host, and optional secure (https) flag and credentials """
        self.host = host
        self.index_name = index_name
        self.secure = secure
        self.credentials = credentials
        self.context = context

    def send(self, data):
        """ Emit (send) a json serialized version of LogRecord to Elastic Host """
        try:
            host = self.host
            if self.secure:
                h = http.client.HTTPSConnection(host, context=self.context)
            else:
                h = http.client.HTTPConnection(host)

            h.putrequest("POST", f"/{self.index_name}/_doc/")

            try:
                send_data = json.dumps({ **{ "index_suffix": self.index_name }, **data }, skipkeys=True, default=lambda x: "err." )
            except Exception:
                raise ValueError(f"object unable to be encoded in ElasticLogEncoder: (index_name) (log_data) (record_args)", self.index_name, data)

            # support multiple hosts on one IP address...
            # need to strip optional :port from host, if present
            i = host.find(":")
            if i >= 0:
                host = host[:i]
                h.putheader("Content-type",
                            "application/json")
                h.putheader("Content-length", str(len(send_data)))
            else:
                raise ValueError(f"host value of {host} for ElasticLogHandler is invalid")
            if self.credentials:
                import base64
                s = ('%s:%s' % self.credentials).encode('utf-8')
                s = 'Basic ' + base64.b64encode(s).strip().decode('ascii')
                h.putheader('Authorization', s)
            h.endheaders()
            h.send(send_data.encode('utf-8'))
            response = h.getresponse()
            # Response Codes
            # https://docs.python.org/3/library/http.html#http-status-codes
            if response.status not in [ 200, 201, 202 ]:
                raise ConnectionError(f"When logging to ElasticHost {host} an invalid response was received {response.status}")
            print( 'Received {} for data from {}'.format(response.status, data["DateTime"]) )
        except Exception:
            raise Exception(f"Error processing record in {self}, data:", send_data)


elastic_host = os.environ['ELASTICSEARCH_HOST']
elastic_index = os.environ['ELASTICSEARCH_INDX']
influxdb_host = os.environ['INFLUXDB_HOST']
influxdb_database = os.environ['INFLUXDB_DATABASE']


import datetime


OUTPUT_ELASTICSEARCH = os.environ['OUTPUT_ELASTICSEARCH'].lower() == "true" if True else False

if OUTPUT_ELASTICSEARCH:
    elastic = ElasticHandler(elastic_host, elastic_index)
    elastic.send({
        "Downstream": modem.getDownstreamChannel(),
        "Upstream": modem.getUpstreamChannel(),
        "Status": modem.getMotoStatusConnectionInfo(),
        "Startup": modem.getMotoStatusStartupSequence(),
        "Uptime": modem.getUptime(),
        # "DateTime": datetime.datetime.now().isoformat()
        "DateTime": datetime.datetime.now(tz=datetime.timezone(-datetime.timedelta(hours=time.altzone / 60 / 60))).isoformat()
    })


influxdb = InfluxDBHandler(influxdb_host, database=influxdb_database)

upstream_data = modem.getUpstreamChannel()
downstream_data = modem.getDownstreamChannel()

upstream_dicts: List[Dict] = []
downstream_dicts: List[Dict] = []
for channel, data in upstream_data.items():
    upstream_dicts.append( {
        "modem": modem.ip,
        "tags": {
            "modem": modem.ip,
            "channel": str(channel)
        },
        "time": datetime.datetime.now(tz=datetime.timezone(-datetime.timedelta(hours=time.altzone / 60 / 60))).isoformat(),
        "measurement": "upstream",
        "fields": data
    } )

for channel, data in downstream_data.items():
    downstream_dicts.append( {
        "modem": modem.ip,
        "tags": {
            "modem": modem.ip,
            "channel": str(channel)
        },
        "time": datetime.datetime.now(tz=datetime.timezone(-datetime.timedelta(hours=time.altzone / 60 / 60))).isoformat(),
        "measurement": "downstream",
        "fields": data
    } )

merged_dicts: List[Dict] = [
    {
        "modem": modem.ip,
        "tags": {
            "modem": modem.ip,
        },
        "time": datetime.datetime.now(tz=datetime.timezone(-datetime.timedelta(hours=time.altzone / 60 / 60))).isoformat(),
        "measurement": "status",
        "fields": modem.getMotoStatusConnectionInfo()
    },
    {
        "modem": modem.ip,
        "tags": {
            "modem": modem.ip,
        },
        "time": datetime.datetime.now(tz=datetime.timezone(-datetime.timedelta(hours=time.altzone / 60 / 60))).isoformat(),
        "measurement": "startup",
        "fields": modem.getMotoStatusStartupSequence()
    },
    {
        "modem": modem.ip,
        "tags": {
            "modem": modem.ip,
        },
        "time": datetime.datetime.now(tz=datetime.timezone(-datetime.timedelta(hours=time.altzone / 60 / 60))).isoformat(),
        "measurement": "uptime",
        "fields": {
            "uptime": modem.getUptime()
        }
    }
]

merged_dicts.extend(upstream_dicts)
merged_dicts.extend(downstream_dicts)

influxdb.send(merged_dicts)
