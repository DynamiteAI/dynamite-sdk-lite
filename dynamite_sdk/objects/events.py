import pandas as pd

from ipaddress import ip_address
from dateutil.parser import parse as date_parse


class InvalidEventError(Exception):
    """
    Thrown when an unexpected raw event format is encountered
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while parsing an event: {}".format(message)
        super(InvalidEventError, self).__init__(msg)


class InvalidConnectionEventError(Exception):
    """
    Thrown when an unexpected raw conn event format is encountered
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while parsing a conn event: {}".format(message)
        super(InvalidConnectionEventError, self).__init__(msg)


class InvalidDhcpEventError(Exception):
    """
    Thrown when an unexpected raw dhcp event format is encountered
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while parsing a dhcp event: {}".format(message)
        super(InvalidDhcpEventError, self).__init__(msg)


class InvalidDnsEventError(Exception):
    """
    Thrown when an unexpected raw dns event format is encountered
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while parsing a dns event: {}".format(message)
        super(InvalidDnsEventError, self).__init__(msg)


class InvalidHttpEventError(Exception):
    """
    Thrown when an unexpected raw http event format is encountered
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while parsing a http event: {}".format(message)
        super(InvalidHttpEventError, self).__init__(msg)


class InvalidSipEventError(Exception):
    """
    Thrown when an unexpected raw sip event format is encountered
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while parsing a sip event: {}".format(message)
        super(InvalidSipEventError, self).__init__(msg)


class InvalidSnmpEventError(Exception):
    """
    Thrown when an unexpected raw snmp event format is encountered
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while parsing a snmp event: {}".format(message)
        super(InvalidSnmpEventError, self).__init__(msg)


class InvalidSshEventError(Exception):
    """
    Thrown when an unexpected raw ssh event format is encountered
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while parsing a ssh event: {}".format(message)
        super(InvalidSshEventError, self).__init__(msg)


class Event:
    """
    Super generic Event; any Zeek/Flow event can be normalized into this object
    """
    def __init__(self, raw_event_document: dict):
        self.raw_event_document = raw_event_document

        self.event_type = None                #: The type of event (Either "flow" or a Zeek log prefix
        self.event_time = None                #: The UTC-0 time at which the event occurred
        self.source_ip_address = None         #: The sender IP in the event
        self.destination_ip_address = None    #: The recipient IP in the event
        self.source_port = None               #: The sender port in the event
        self.destination_port = None          #: The recipient port in the event
        self.elasticsearch_index = None       #: The ElasticSearch index where the event was found
        self.originating_agent_tag = None     #: The friendly name of the agent (Zeek events only)
        self.forwarder_type = None            #: Either "zeek" or "netflow"
        self.node_ip_address = None           #: The ip_address of the originating host (collector/agent IP)
        self.node_hostname = None             #: The hostname of the originating host (collector/agent hostname)
        self.uid = None                       #: The unique id for the Zeek connection

        self._parse_raw_event()

    def _parse_raw_event(self) -> None:
        """
        Parse common zeek/flow fields

        :return: None
        """
        try:
            self.elasticsearch_index = self.raw_event_document['_index']
        except KeyError:
            raise InvalidEventError('Missing index field')
        try:
            _source = self.raw_event_document['_source']
        except KeyError:
            raise InvalidEventError('Missing _source section')
        try:
            self.node_ip_address = ip_address(_source['node']['ipaddr'])
        except KeyError:
            raise InvalidEventError('Missing node_ip_address field')
        except ValueError:
            raise InvalidEventError('Invalid node_ip_address field [{}]'.format(_source['node']['ipaddr']))
        try:
            self.originating_agent_tag = _source['fields']['originating_agent_tag']
            self.forwarder_type = 'zeek'
        except KeyError:
            self.forwarder_type = 'netflow'
        try:
            self.node_hostname = _source['node']['hostname']
        except KeyError:
            raise InvalidEventError('Missing node_hostname field')
        try:
            self.event_type = _source['event_type']
        except KeyError:
            raise InvalidEventError('Missing event_type field')
        try:
            self.event_time = date_parse(_source['@timestamp'])
        except KeyError:
            raise InvalidEventError('Missing event_time field')
        except ValueError:
            raise InvalidEventError('Invalid event_time field [{}]'.format(_source['@timestamp']))
        try:
            self.source_ip_address = _source['flow']['src_addr']
        except KeyError:
            try:
                self.source_ip_address = _source['zeek']['id.orig_h']
            except KeyError:
                try:
                    self.source_ip_address = _source['zeek']['client_addr']
                except KeyError:
                    InvalidEventError('Missing source_ip_addressess field')
        try:
            self.source_ip_address = ip_address(self.source_ip_address)
        except ValueError:
            raise InvalidEventError('Invalid source_ip_address field [{}]'.format(self.source_ip_address))
        try:
            self.destination_ip_address = _source['flow']['dst_addr']
        except KeyError:
            try:
                self.destination_ip_address = _source['zeek']['id.resp_h']
            except KeyError:
                try:
                    self.destination_ip_address = _source['zeek']['server_addr']
                except KeyError:
                    InvalidEventError('Missing destination_ip_address field')
        try:
            self.destination_ip_address = ip_address(self.destination_ip_address)
        except ValueError:
            raise ('Invalid destination_ip_addr field [{}]'.format(self.destination_ip_address))
        try:
            self.source_port = _source['flow']['src_port']
        except KeyError:
            try:
                self.source_port = _source['zeek']['id.orig_p']
            except KeyError:
                try:
                    self.source_port = _source['zeek']['client_port']
                except KeyError:
                    pass
        try:
            self.destination_port = _source['flow']['dst_port']
        except KeyError:
            try:
                self.destination_port = _source['zeek']['id.resp_p']
            except KeyError:
                try:
                    self.destination_port = _source['zeek']['server_port']
                except KeyError:
                    pass
        try:
            self.uid = _source['zeek']['uid']
        except KeyError:
            try:
                self.uid = _source['zeek']['uids'][0]
            except (KeyError, IndexError):
                pass

    def __str__(self):
        """
        :return: High-level representation of the connection

        [ssl][2017-10-09 15:52:34+00:00]192.168.1.201:39334 -> 192.168.1.250:443
        """
        return '[{}][{}][{}]{}:{} -> {}:{}'.format(self.forwarder_type, self.event_type, self.event_time,
                                                   self.source_ip_address, self.source_port,
                                                   self.destination_ip_address, self.destination_port)

    def to_dataframe(self) -> pd.DataFrame:
        """

        :return: 1x1 DataFrame of heading and event fields
        """
        ignore_vars = ['raw_event_document', 'attributes']
        headers = [var for var in vars(self) if var not in ignore_vars]
        data = [[getattr(self, header) for header in headers]]
        return pd.DataFrame(data, columns=headers)


class ConnectionEvent(Event):
    
    """
    Represents a log generated either by a NetFlow forwarder OR Zeek conn.log

    https://docs.zeek.org/en/stable/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info
    """

    def __init__(self, raw_event_document: dict):
        super().__init__(raw_event_document)
        self.ip_protocol = None                    #: Layer3 transport protocol TCP/UDP/ICMP
        self.total_bytes = None                    #: Total bytes both sent and received
        self.total_packets = None                  #: Total packets sent
        self.service_port = None                   #: A recognized service port (non-ephemeral)
        self.client_ip_address = None              #: The IP address of the client in the conversation
        self.server_ip_address = None              #: The IP address of the server in the conversation
        self.client_hostname = None                #: The hostname of the client in the conversation
        self.server_hostname = None                #: The hostname of the server in the conversation
        self.source_mac_address = None             #: The Layer2 MAC address of the source device
        self.destination_mac_address = None        #: The Layer2 MAC address of the destination device
        self.source_autonomous_system = None       #: The name corresponding to an ASN for the source system
        self.destination_autonomous_system = None  #: The name corresponding to an ASN for the destination system
        self.client_autonomous_system = None       #: The name corresponding to an ASN for the client system
        self.server_autonomous_system = None       #: The name corresponding to an ASN for the server system
        self.source_city = None                    #: The city for the source in the conversation
        self.source_country = None                 #: The country for the source in the conversation
        self.source_country_code = None            #: The country code for the source in the conversation
        self.source_geo_location = None            #: The geographical coordinates for the source in the conversation
        self.destination_city = None               #: The city for the destination in the conversation
        self.destination_country = None            #: The country for the destination in the conversation
        self.destination_country_code = None       #: The country code for the destination in the conversation
        self.destination_geo_location = None       #: The geographical coordinates for the dst in the conversation
        self.client_city = None                    #: The city for the client in the conversation
        self.client_country = None                 #: The country for the client in the conversation
        self.client_country_code = None            #: The country code for the client in the conversation
        self.client_geo_location = None            #: The geographical coordinates for the client in the conversation
        self.server_city = None                    #: The city for the server in the conversation
        self.server_country = None                 #: The country for the server in the conversation
        self.server_country_code = None            #: The country code for the server in the conversation
        self.server_geo_location = None            #: The geographical coordinates for the server in the conversation

        # Zeek Only
        self.service = None                        #: An identification of an application protocol being sent
        self.connection_state = None               #: The state of the connection
        self.duration = None                       #: The number of seconds for a given connection
        self.originated_locally = None             #: True, if the connection originated from inside the network
        self.source_bytes = None                   #: The number of bytes sent
        self.destination_bytes = None              #: The number of bytes received
        self.source_packets = None                 #: The number of packets sent
        self.destination_packets = None            #: The number of packets received
        self.history = None                        #: The state history of connections as a string of letters
        self.uid = None                            #: A unique identifier for the connection
        self._parse_raw_conn_event()
        delattr(self, 'raw_event_document')

    def _parse_raw_conn_event(self) -> None:
        if self.event_type != 'conn':
            raise InvalidConnectionEventError('Invalid conn record, got [{}]'.format(self.event_type))
        _source = self.raw_event_document['_source']
        self.ip_protocol = _source['flow'].get('ip_protocol')
        self.total_bytes = _source['flow'].get('bytes')
        self.total_packets = _source['flow'].get('packets')
        self.service_port = _source['flow'].get('service_port')
        self.client_ip_address = _source['flow'].get('client_addr')
        self.server_ip_address = _source['flow'].get('server_addr')
        self.client_hostname = _source['flow'].get('client_hostname')
        self.server_hostname = _source['flow'].get('server_hostname')
        self.source_mac_address = _source['flow'].get('source_mac_address')
        self.destination_mac_address = _source['flow'].get('destination_mac_address')
        self.source_autonomous_system = _source['flow'].get('src_autonomous_system')
        self.destination_autonomous_system = _source['flow'].get('dst_autonomous_system')
        self.client_autonomous_system = _source['flow'].get('client_autonomous_system')
        self.server_autonomous_system = _source['flow'].get('server_autonomous_system')
        self.source_city = _source['flow'].get('src_city')
        self.source_country = _source['flow'].get('src_country')
        self.source_country_code = _source['flow'].get('src_country_code')
        self.destination_city = _source['flow'].get('dst_city')
        self.destination_country = _source['flow'].get('dst_country')
        self.destination_country_code = _source['flow'].get('dst_country_code')
        self.client_city = _source['flow'].get('client_city')
        self.client_country = _source['flow'].get('client_country')
        self.client_country_code = _source['flow'].get('client_country_code')
        self.server_city = _source['flow'].get('server_city')
        self.server_country = _source['flow'].get('server_country')
        self.server_country_code = _source['flow'].get('server_country_code')

        source_geo_location = _source['flow'].get('src_geo_location')
        destination_geo_location = _source['flow'].get('dst_geo_location')
        if isinstance(source_geo_location, dict):
            self.source_geo_location = source_geo_location.get('lat'), source_geo_location.get('lon')
        if isinstance(destination_geo_location, dict):
            self.destination_geo_location = destination_geo_location.get('lat'), destination_geo_location.get('lon')
        self.client_geo_location = _source['flow'].get('client_geo_location')
        self.server_geo_location = _source['flow'].get('server_geo_location')

        try:
            self.client_ip_address = ip_address(self.client_ip_address)
        except ValueError:
            InvalidConnectionEventError('Invalid client_ip_address field')
        try:
            self.server_ip_address = ip_address(self.server_ip_address)
        except ValueError:
            InvalidConnectionEventError('Invalid server_ip_address field')

        # Get Zeek specific conn.log fields
        try:
            self.service = _source['zeek'].get('service')
            self.connection_state = _source['zeek'].get('conn_state')
            self.duration = _source['zeek'].get('duration')
            self.originated_locally = _source['zeek'].get('local_orig')
            self.history = _source['zeek'].get('history')
            self.uid = _source['zeek'].get('uid')
            orig_ip_bytes = _source['zeek'].get('orig_ip_bytes')
            orig_bytes = _source['zeek'].get('orig_ip_bytes')
            resp_ip_bytes = _source['zeek'].get('resp_ip_bytes')
            resp_bytes = _source['zeek'].get('resp_bytes')
            if orig_bytes and orig_ip_bytes:
                self.source_bytes = max([orig_ip_bytes, orig_bytes])
            if resp_bytes and resp_ip_bytes:
                self.destination_bytes = max([resp_ip_bytes, resp_bytes])
            self.source_packets = _source['zeek'].get('orig_pkts')
            self.destination_packets = _source['zeek'].get('resp_pkts')
        except KeyError:
            pass

    def __str__(self) -> str:
        """
        :return: A JSON representation of the ConnectionEvent
        """
        return str(vars(self))


class DhcpEvent(Event):
    """
    Represents a Zeek dhcp.log

    https://docs.zeek.org/en/stable/scripts/base/protocols/dhcp/main.zeek.html#type-DHCP::Info
    """

    def __init__(self, raw_event_document: dict):
        super().__init__(raw_event_document)

        self.client_ip_address = None     #: The IP address of the client requesting the DHCP lease
        self.server_ip_address = None     #: The IP address of the server involved in actually handing out the lease
        self.client_port = None           #: Client port # seen at time of server handing out IP (expected as 68/udp)
        self.server_port = None           #: Server port # seen at time of server handing out IP (expected as 67/udp).
        self.mac_address = None           #: Client’s hardware address
        self.hostname = None              #: Name given by client in Hostname
        self.client_fqdn = None           #: FQDN given by client in Client FQDN
        self.domain = None                #: Domain given by the server
        self.requested_ip_address = None  #: IP address requested by the client
        self.assigned_ip_address = None   #: IP address assigned by the server
        self.lease_time = None            #: IP address lease interval (seconds)
        self.client_message = None        #: Message typically accompanied with a DHCP_DECLINE
        self.server_message = None        #: Message typically accompanied with a DHCP_NAK
        self.message_types = None         #: The DHCP message types seen by this DHCP transaction
        self.duration = None              #: The time from the first message to the last
        self.uids = None                  #: Series of unique ids of the connections over which DHCP is occurring.
        self._parse_raw_dhcp_event()
        delattr(self, 'raw_event_document')

    def _parse_raw_dhcp_event(self) -> None:
        if self.event_type != 'dhcp':
            raise InvalidDhcpEventError('Invalid dhcp record, got [{}]'.format(self.event_type))
        _source = self.raw_event_document['_source']
        try:
            self.client_port = _source['zeek'].get('client_port')
            self.server_port = _source['zeek'].get('server_port')
            self.mac_address = _source['zeek'].get('mac')
            self.hostname = _source['zeek'].get('host_name')
            self.client_fqdn = _source['zeek'].get('client_fqdn')
            self.domain = _source['zeek'].get('domain')
            self.requested_ip_address = _source['zeek'].get('requested_addr')
            self.assigned_ip_address = _source['zeek'].get('assigned_addr')
            self.lease_time = _source['zeek'].get('lease_time')
            self.client_message = _source['zeek'].get('client_message')
            self.server_message = _source['zeek'].get('server_message')
            self.message_types = _source['zeek'].get('msg_types')
            self.duration = _source['zeek'].get('duration')
            self.uids = _source['zeek'].get('uids')
            try:
                self.client_ip_address = ip_address(_source['zeek'].get('client_addr'))
            except ValueError:
                raise InvalidDhcpEventError('Invalid client_ip_address field [{}]'.format(self.client_ip_address))
            try:
                self.server_ip_address = _source['zeek'].get('server_addr')
            except ValueError:
                raise InvalidDhcpEventError('Invalid server_ip_address field [{}]'.format(self.server_ip_address))
        except KeyError:
            raise InvalidDhcpEventError('Invalid dhcp record, missing "zeek" section')

    def __str__(self) -> str:
        """
        :return: A JSON representation of the DhcpEvent
        """
        return str(vars(self))


class DnsEvent(Event):

    """
    Represents a Zeek dns.log

    https://docs.zeek.org/en/stable/scripts/base/protocols/dns/main.zeek.html#type-DNS::Info
    """

    def __init__(self, raw_event_document: dict):
        super().__init__(raw_event_document)

        self.authoritative_answer = None    #: True if the responding server is an authority for the domain name
        self.recursion_available = None     #: True if server supports recursive queries
        self.recursion_desired = None       #: True if the client wants recursive service for this query
        self.message_truncated = None       #: True if the message was truncated
        self.rejected = None                #: True if the DNS query was rejected by the server
        self.answers = None                 #: A set of resource descriptions in the query answer
        self.query_type = None              #: A QTYPE value specifying the type of the query
        self.query_type_name = None         #: A descriptive name for the type of the query
        self.query_class = None             #: The QCLASS value specifying the class of the query
        self.query_class_name = None        #: A descriptive name for the class of the query
        self.query = None                   #: The domain name that is the subject of the DNS query
        self.response_code = None           #: The response code value in DNS response messages
        self.response_code_name = None      #: A descriptive name for the response code value
        self.transaction_id = None          #: A 16-bit identifier assigned by the program that generated the DNS query
        self.round_trip_time = None         #: The delay between when the request was seen until the answer started
        self._parse_raw_dns_event()
        delattr(self, 'raw_event_document')

    def _parse_raw_dns_event(self) -> None:
        if self.event_type != 'dns':
            raise InvalidDnsEventError('Invalid dns record, got [{}]'.format(self.event_type))
        _source = self.raw_event_document['_source']
        try:
            self.authoritative_answer = _source['zeek'].get('AA')
            self.recursion_available = _source['zeek'].get('RA')
            self.recursion_desired = _source['zeek'].get('RD')
            self.message_truncated = _source['zeek'].get('TC')
            self.rejected = _source['zeek'].get('rejected')
            self.answers = _source['zeek'].get('answers')
            self.query_type = _source['zeek'].get('qtype')
            self.query_type_name = _source['zeek'].get('qtype_name')
            self.query_class = _source['zeek'].get('qclass')
            self.query_class_name = _source['zeek'].get('qclass_name')
            self.query = _source['zeek'].get('query')
            self.response_code = _source['zeek'].get('rcode')
            self.response_code_name = _source['zeek'].get('rcode_name')
            self.transaction_id = _source['zeek'].get('trans_id')
            self.round_trip_time = _source['zeek'].get('rtt')
        except KeyError:
            raise InvalidDnsEventError('Invalid dns record, missing "zeek" section')

    def __str__(self) -> str:
        """
        :return: A JSON representation of the DnsEvent
        """
        return str(vars(self))


class HttpEvent(Event):
    """
    Represents a Zeek http.log

    https://docs.zeek.org/en/stable/scripts/base/protocols/http/main.zeek.html#type-HTTP::Info
    """

    def __init__(self, raw_event_document: dict):
        super().__init__(raw_event_document)

        self.transaction_depth = None       #: The depth into the connection of this request/response transaction
        self.method = None                  #: Verb used in the HTTP request (GET, POST, HEAD, etc.)
        self.host = None                    #: Value of the HOST header
        self.uri = None                     #: URI used in the request
        self.referrer = None                #: Value of the “referer” header
        self.version = None                 #: Value of the version portion of the request
        self.user_agent = None              #: Value of the User-Agent header from the client
        self.origin = None                  #: Value of the Origin header from the client
        self.request_body_length = None     #: Actual uncompressed content size of the data transferred from the client
        self.response_body_length = None    #: Actual uncompressed content size of the data transferred from the server
        self.status_code = None             #: Status code returned by the server
        self.status_message = None          #: Status message returned by the server
        self.info_code = None               #: Last seen 1xx informational reply code returned by the server
        self.info_message = None            #: Last seen 1xx informational reply message returned by the server
        self.username = None                #: Username if basic-auth is performed for the request
        self.password = None                #: Password if basic-auth is performed for the request
        self.proxied = None                 #: All of the headers that may indicate if the request was proxied
        self.originating_fuids = None       #: An ordered list of file unique IDs from the client
        self.originating_filenames = None   #: An ordered list of filenames from the client
        self.originating_mime_types = None  #: An ordered list of mime types from the client
        self.recipient_fuids = None         #: An ordered list of file unique IDs from the server
        self.recipient_filenames = None     #: An ordered list of filenames from the server
        self.recipient_mime_types = None    #: An ordered list of mime types from the server
        self.client_header_names = None     #: The list of HTTP header names sent by the client
        self.server_header_names = None     #: The list of HTTP header names sent by the server
        self.cookie_variables = None        #: Variable names extracted from all cookies
        self.uri_variables = None           #: Variable names from the URI
        self._parse_raw_http_event()
        delattr(self, 'raw_event_document')

    def _parse_raw_http_event(self) -> None:
        if self.event_type != 'http':
            raise InvalidHttpEventError('Invalid http record, got [{}]'.format(self.event_type))
        _source = self.raw_event_document['_source']
        try:
            self.transaction_depth = _source['zeek'].get('trans_depth')
            self.method = _source['zeek'].get('method')
            self.host = _source['zeek'].get('host')
            self.uri = _source['zeek'].get('uri')
            self.referrer = _source['zeek'].get('referrer')
            self.version = _source['zeek'].get('version')
            self.user_agent = _source['zeek'].get('user_agent')
            self.origin = _source['zeek'].get('origin')
            self.request_body_length = _source['zeek'].get('request_body_len')
            self.response_body_length = _source['zeek'].get('response_body_len')
            self.status_code = _source['zeek'].get('status_code')
            self.status_message = _source['zeek'].get('status_msg')
            self.info_code = _source['zeek'].get('info_code')
            self.info_message = _source['zeek'].get('info_msg')
            self.username = _source['zeek'].get('username')
            self.password = _source['zeek'].get('password')
            self.proxied = _source['zeek'].get('proxied')
            self.originating_fuids = _source['zeek'].get('orig_fuids')
            self.originating_filenames = _source['zeek'].get('orig_filenames')
            self.originating_mime_types = _source['zeek'].get('orig_mime_types')
            self.recipient_fuids = _source['zeek'].get('resp_fuids')
            self.recipient_filenames = _source['zeek'].get('resp_filenames')
            self.recipient_mime_types = _source['zeek'].get('resp_mime_types')
            self.client_header_names = _source['zeek'].get('client_header_names')
            self.server_header_names = _source['zeek'].get('server_header_names')
            self.cookie_variables = _source['zeek'].get('cookie_variables')
            self.uri_variables = _source['zeek'].get('uri_variables')
        except KeyError:
            raise InvalidHttpEventError('Invalid http record, missing "zeek" section')

    def __str__(self) -> str:
        """
        :return: A JSON representation of the HttpEvent
        """
        return str(vars(self))


class SipEvent(Event):
    """
    Represents a Zeek sip.log

    https://docs.zeek.org/en/stable/scripts/base/protocols/sip/main.zeek.html#type-SIP::Info
    """
    def __init__(self, raw_event_document: dict):
        super().__init__(raw_event_document)

        self.transaction_depth = None       #: The depth into the connection of this request/response transaction
        self.method = None                  #: Verb used in the SIP request (INVITE, REGISTER etc)
        self.uri = None                     #: URI used in the request
        self.request_from = None            #: Contents of the request From: header
        self.request_to = None              #: Contents of the To: header
        self.response_from = None           #: Contents of the response From: header
        self.response_to = None             #: Contents of the response To: header
        self.reply_to = None                #: Contents of the Reply-To: header
        self.call_id = None                 #: Contents of the Call-ID: header from the client
        self.c_sequence = None              #: Contents of the CSeq: header from the client
        self.subject = None                 #: Contents of the Subject: header from the client
        self.request_path = None            #: The client message transmission path, as extracted from the headers
        self.response_path = None           #: The server message transmission path, as extracted from the headers
        self.user_agent = None              #: Contents of the User-Agent: header from the client
        self.status_code = None             #: Status code returned by the server
        self.status_message = None          #: Status message returned by the server
        self.warning = None                 #: Contents of the Warning: header
        self.request_body_length = None     #: Contents of the Content-Length: header from the client
        self.response_body_length = None    #: Contents of the Content-Length: header from the server
        self.content_type = None            #: Contents of the Content-Type: header from the server
        self._parse_raw_sip_event()
        delattr(self, 'raw_event_document')

    def _parse_raw_sip_event(self) -> None:
        if self.event_type != 'sip':
            raise InvalidHttpEventError('Invalid sip record, got [{}]'.format(self.event_type))
        _source = self.raw_event_document['_source']
        try:
            self.transaction_depth = _source['zeek'].get('trans_depth')
            self.method = _source['zeek'].get('method')
            self.uri = _source['zeek'].get('uri')
            self.request_from = _source['zeek'].get('request_from')
            self.request_to = _source['zeek'].get('request_to')
            self.response_from = _source['zeek'].get('response_from')
            self.response_to = _source['zeek'].get('response_to')
            self.reply_to = _source['zeek'].get('reply_to')
            self.call_id = _source['zeek'].get('call_id')
            self.c_sequence = _source['zeek'].get('seq')
            self.subject = _source['zeek'].get('subject')
            self.request_path = _source['zeek'].get('request_path')
            self.response_path = _source['zeek'].get('response_path')
            self.user_agent = _source['zeek'].get('user_agent')
            self.status_code = _source['zeek'].get('status_code')
            self.status_message = _source['zeek'].get('status_message')
            self.warning = _source['zeek'].get('warning')
            self.request_body_length = _source['zeek'].get('request_body_len')
            self.response_body_length = _source['zeek'].get('response_body_len')
        except KeyError:
            raise InvalidSipEventError('Invalid sip record, missing "zeek" section')

    def __str__(self) -> str:
        """
        :return: A JSON representation of the SipEvent
        """
        return str(vars(self))


class SnmpEvent(Event):
    """
    Represents a Zeek snmp.log

    https://docs.zeek.org/en/stable/scripts/base/protocols/snmp/main.zeek.html#type-SNMP::Info
    """

    def __init__(self, raw_event_document: dict):
        super().__init__(raw_event_document)

        self.duration = None           #: The time between first/last packet sent in SNMP session
        self.version = None            #: The version of SNMP being used
        self.community_string = None   #: The community string of the first SNMP packet associated with the session
        self.get_requests = None       #: The number of variable bindings in GetRequest/GetNextRequest PDUs seen
        self.get_bulk_requests = None  #: The number of variable bindings in GetBulkRequest PDUs seen
        self.get_responses = None      #: The number of variable bindings in GetResponse/Response PDUs
        self.set_requests = None       #: The number of variable bindings in SetRequest PDUs seen for the session
        self.display_string = None     #: The system description of the SNMP responder endpoint
        self.up_since = None           #: The time at which the SNMP responder endpoint claims it’s been up since
        self._parse_raw_snmp_event()
        delattr(self, 'raw_event_document')

    def _parse_raw_snmp_event(self) -> None:
        if self.event_type != 'snmp':
            raise InvalidHttpEventError('Invalid snmp record, got [{}]'.format(self.event_type))
        _source = self.raw_event_document['_source']
        try:
            self.duration = _source['zeek'].get('duration')
            self.version = _source['zeek'].get('version')
            self.community_string = _source['zeek'].get('community')
            self.get_requests = _source['zeek'].get('get_requests')
            self.get_bulk_requests = _source['zeek'].get('get_bulk_requests')
            self.get_responses = _source['zeek'].get('get_responses')
            self.set_requests = _source['zeek'].get('set_requests')
            self.display_string = _source['zeek'].get('display_string')
            self.up_since = _source['zeek'].get('up_since')
        except KeyError:
            raise InvalidSipEventError('Invalid snmp record, missing "zeek" section')

    def __str__(self) -> str:
        """
        :return: A JSON representation of the SnmpEvent
        """
        return str(vars(self))


class SshEvent(Event):
    """
    Represents a Zeek ssh.log

    https://docs.zeek.org/en/stable/scripts/base/protocols/ssh/main.zeek.html#type-SSH::Info
    """

    def __init__(self, raw_event_document: dict):
        super().__init__(raw_event_document)

        self.version = None                  #: SSH major version (1 or 2)
        self.authentication_success = None   #: True if successfully authenticated
        self.authentication_attempts = None  #: The number of authentication attempts observed
        self.direction = None                #: Direction of the connection (Outbound/Inbound)
        self.client_version_string = None    #: The client's version string
        self.server_version_string = None    #: The server's version string
        self.cipher_algorithm = None         #: The encryption algorithm in use
        self.mac_algorithm = None            #: The signing (MAC) algorithm in use
        self.compression_algorithm = None    #: The compression algorithm in use
        self.key_algorithm = None            #: The key exchange algorithm in use
        self.host_key_algorithm = None       #: The server host key’s algorithm
        self.host_key = None                 #: The server’s key fingerprint
        self._parse_raw_ssh_event()
        delattr(self, 'raw_event_document')

    def _parse_raw_ssh_event(self) -> None:
        if self.event_type != 'ssh':
            raise InvalidSshEventError('Invalid ssh record, got [{}]'.format(self.event_type))
        _source = self.raw_event_document['_source']
        try:
            self.version = _source['zeek'].get('version')
            self.authentication_success = _source['zeek'].get('auth_success')
            self.authentication_attempts = _source['zeek'].get('auth_attempts')
            self.direction = _source['zeek'].get('direction')
            self.client_version_string = _source['zeek'].get('client')
            self.server_version_string = _source['zeek'].get('server')
            self.cipher_algorithm = _source['zeek'].get('cipher_alg')
            self.mac_algorithm = _source['zeek'].get('mac_alg')
            self.compression_algorithm = _source['zeek'].get('compression_alg')
            self.key_algorithm = _source['zeek'].get('key_alg')
            self.host_key_algorithm = _source['zeek'].get('host_key_alg')
            self.host_key = _source['zeek'].get('host_key')
        except KeyError:
            raise InvalidSshEventError('Invalid ssh record, missing "zeek" section')

    def __str__(self) -> str:
        """
        :return: A JSON representation of the SshEvent
        """
        return str(vars(self))
