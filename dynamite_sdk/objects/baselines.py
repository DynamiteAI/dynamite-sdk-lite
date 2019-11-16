import pandas as pd

from ipaddress import ip_address
from dateutil.parser import parse as date_parse


class InvalidIntervalError(Exception):
    """
    Thrown when an unexpected raw interval format is encountered
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while parsing an interval: {}".format(message)
        super(InvalidIntervalError, self).__init__(msg)


class Interval:

    def __init__(self, raw_interval_document: dict):
        self.raw_interval_document = raw_interval_document

        self.elasticsearch_index = None                          #: The ElasticSearch index where the interval was found
        self.originating_agent_tag = None                        #: The friendly name of the agent
        self.forwarder_type = None                               #: Always "zeek"
        self.event_type = None                                   #: Always "netbase"
        self.node_ip_address = None                              #: The ip_address of the originating host (collector/agent IP)
        self.node_hostname = None                                #: The hostname of the originating host (collector/agent hostname)
        self.address = None                                      #: The monitored IP address
        self.start_time = None                                   #: Start time of the observation
        self.end_time = None                                     #: End time of the observation
        self.interval_size = None                                #: The time between start_time and end_time
        self.internal_port_count = None                          #: Count of unique ports communicated with internally
        self.internal_host_count = None                          #: Count of unique hosts communicated with internally
        self.external_port_count = None                          #: Count of unique ports communicated with externally
        self.external_host_count = None                          #: Count of unique hosts communicated with externally
        self.internal_client_count = None                        #: Count of unique internal clients communicating with this IP
        self.external_client_count = None                        #: Count fo unique external clients communicating with this IP
        self.connection_count = None                            #: Total count of connections this IP was involved in
        self.originating_connection_count = None                 #: Total count of external conns originated by this IP
        self.successful_originating_connection_count = None      #: Count of outbound conns originated by this IP that were successful
        self.rejected_originating_connection_count = None        #: Count of outbound conns originated by this IP that were rejected
        self.originating_to_highport_count = None                #: Count of outbound conns originated by this IP to ports >= 1024
        self.originating_to_lowport_count = None                 #: Count of outbound conns originated by this IP to ports < 1024
        self.originating_to_service_count = None                 #: Count of outbound conns  originated by this IP to a recognized service
        self.internal_originating_connection_count = None        #: Count of internal connections by this host
                                                                 #: Count of internal conns originated by this host that were rejected
        self.internal_originating_rejected_connection_count = None 
        self.internal_to_highport_count = None                   #: Count of internal conns to ports >= 1024
        self.internal_to_lowport_count = None                    #: Count of internal conns to ports < 1024
        self.internal_to_service_count = None                    #: Count of internal conns to recognized server
        self.internal_received_connection_count = None          #: Count of internal conns this IP responded to
        self.internal_originating_bytes_sent_sum = None          #: Sum of bytes sent as originator in internal conns
        self.internal_originating_bytes_received_sum = None      #: Sum of bytes received as originator in internal conns
        self.external_originating_bytes_sent_sum = None          #: Sum of bytes sent as originator in external conns
        self.external_originating_bytes_received_sum = None      #: Sum of bytes received as originator in external conns
        self.internal_originating_packets_sent_count = None      #: Count of packets sent in internal conns
        self.internal_originating_packets_received_count = None  #: Count of packets recevied in internal conns
        self.external_originating_packets_sent_count = None      #: Count of packets sent as originator in outbound conns
        self.external_originating_packets_received_count = None  #: Count of packets received as originator in outbound conns
        self.smb_client_connection_count = None                  #: Count of SMB connections as a client
        self.smb_server_connection_count = None                  #: Count of SMB connections as a server
        self.smb_producer_consumer_ratio_average = None          #: Avg pcr for smb connections
        self.smb_producer_consumer_ratio_max = None              #: Max pcr for smb connections
        self.smb_producer_consumer_ratio_min = None              #: Min pcr for smb connections
        self.http_client_connection_count = None                 #: Count of http connections as client
        self.http_server_connection_count = None                 #: Count of http connections as server
        self.http_producer_consumer_ratio_average = None         #: Avg pcr for http connections
        self.http_producer_consumer_ratio_max = None             #: Max pcr for http connections
        self.http_producer_consumer_ratio_min = None             #: Min pcr for http connections
        self.dns_client_connection_count = None                  #: Count of dns connections as client
        self.dns_server_connection_count = None                  #: Count of dns connections as server
        self.dns_producer_consumer_ratio_average = None          #: Avg pcr for dns connections
        self.dns_producer_consumer_ratio_max = None              #: Max pcr for dns connections
        self.dns_producer_consumer_ratio_min = None              #: Min pcr for dns connections
        self.ssl_client_connection_count = None                  #: Count of ssl connections as client
        self.ssl_server_connection_count = None                  #: Count of ssl connections as server
        self.ssl_producer_consumer_ratio_average = None          #: Avg pcr for ssl connections
        self.ssl_producer_consumer_ratio_max = None              #: Max pcr for ssl connections
        self.ssl_producer_consumer_ratio_min = None              #: Min pcr for ssl connections
        self.rdp_client_connection_count = None                  #: Count of rdp connections as client
        self.rdp_server_connection_count = None                  #: Count of rdp connections as server
        self.rdp_producer_consumer_ratio_average = None          #: Avg pcr for rdp connections
        self.rdp_producer_consumer_ratio_max = None              #: Max pcr for rdp connections
        self.rdp_producer_consumer_ratio_min = None              #: Min pcr for rdp connections
        self._parse_raw_interval()
        delattr(self, 'raw_interval_document')

    def _parse_raw_interval(self) -> None:
        try:
            self.elasticsearch_index = self.raw_interval_document['_index']
        except KeyError:
            raise InvalidIntervalError('Missing index field')
        try:
            _source = self.raw_interval_document['_source']
        except KeyError:
            raise InvalidIntervalError('Missing _source section')
        try:
            self.node_ip_address = ip_address(_source['node']['ipaddr'])
        except KeyError:
            raise InvalidIntervalError('Missing node_ip_address field')
        except ValueError:
            raise InvalidIntervalError('Invalid node_ip_address field [{}]'.format(_source['node']['ipaddr']))
        try:
            self.originating_agent_tag = _source['fields']['originating_agent_tag']
            self.forwarder_type = 'zeek'
        except KeyError:
            raise InvalidIntervalError('Missing originating_agent_tag')
        try:
            self.node_hostname = _source['node']['hostname']
        except KeyError:
            raise InvalidIntervalError('Missing node_hostname field')
        try:
            self.event_type = _source['event_type']
        except KeyError:
            raise InvalidIntervalError('Missing event_type field')
        try:
            try:
                self.start_time = date_parse(_source['zeek']['starttime'])
            except KeyError:
                raise InvalidIntervalError('Missing starttime field')
            except ValueError:
                raise InvalidIntervalError('Invalid start_time field [{}]'.format(_source['zeek']['starttime']))
            try:
                self.end_time = date_parse(_source['zeek']['endtime'])
            except KeyError:
                raise InvalidIntervalError('Missing endtime field')
            except ValueError:
                raise InvalidIntervalError('Invalid end_time field [{}]'.format(_source['zeek']['endtime']))
            try:
                self.address = ip_address(_source['zeek']['address'])
            except KeyError:
                raise InvalidIntervalError('Missing address field')
            except ValueError:
                raise InvalidIntervalError('Invalid address field [{}]'.format(_source['zeek']['address']))
            self.interval_size = self.end_time - self.start_time
            self.internal_port_count = _source['zeek'].get('int_port_cnt', 0)
            self.internal_host_count = _source['zeek'].get('int_host_cnt', 0)
            self.external_ports = _source['zeek'].get('ext_ports', 0)
            self.external_port_count = _source['zeek'].get('ext_port_cnt', 0)
            self.external_host_count = _source['zeek'].get('ext_host_cnt', 0)
            self.internal_client_count = _source['zeek'].get('int_client_cnt', 0)
            self.external_client_count = _source['zeek'].get('ext_client_cnt', 0)
            self.connection_count = _source['zeek'].get('total_conns', 0)
            self.originating_connection_count = _source['zeek'].get('out_orig_conns', 0)
            self.successful_originating_connection_count = _source['zeek'].get('out_succ_conns', 0)
            self.rejected_originating_connection_count = _source['zeek'].get('out_rej_conns', 0)
            self.originating_to_highport_count = _source['zeek'].get('out_to_highports', 0)
            self.originating_to_lowport_count = _source['zeek'].get('out_to_lowports', 0)
            self.originating_to_service_count = _source['zeek'].get('out_to_service', 0)
            self.internal_originating_connection_count = _source['zeek'].get('int_orig_conns', 0)
            self.internal_originating_rejected_connection_count = _source['zeek'].get('int_rej_conns', 0)
            self.internal_to_highport_count = _source['zeek'].get('int_to_highports', 0)
            self.internal_to_lowport_count = _source['zeek'].get('int_to_lowports', 0)
            self.internal_to_service_count = _source['zeek'].get('int_to_service', 0)
            self.internal_received_connection_count = _source['zeek'].get('int_resp_conns', 0)
            self.internal_originating_bytes_sent_sum = _source['zeek'].get('int_orig_bytes_sent', 0)
            self.internal_originating_bytes_received_sum = _source['zeek'].get('int_orig_bytes_rcvd', 0)
            self.external_originating_bytes_sent_sum = _source['zeek'].get('out_orig_bytes_sent', 0)
            self.external_originating_bytes_received_sum = _source['zeek'].get('out_orig_bytes_rcvd', 0)
            self.internal_originating_packets_sent_count = _source['zeek'].get('int_orig_pkts_sent', 0)
            self.internal_originating_packets_received_count = _source['zeek'].get('int_orig_pkts_recvd', 0)
            self.external_originating_packets_sent_count = _source['zeek'].get('out_orig_pkts_sent', 0)
            self.external_originating_packets_received_count = _source['zeek'].get('out_orig_pkts_recvd', 0)
            self.smb_client_connection_count = _source['zeek'].get('smb_client_conns', 0)
            self.smb_server_connection_count = _source['zeek'].get('smb_server_conns', 0)
            self.smb_producer_consumer_ratio_average = _source['zeek'].get('pcr_smb_avg', 0)
            self.smb_producer_consumer_ratio_max = _source['zeek'].get('pcr_smb_max', 0)
            self.smb_producer_consumer_ratio_min = _source['zeek'].get('pcr_smb_min', 0)
            self.http_client_connection_count = _source['zeek'].get('http_client_conns', 0)
            self.http_server_connection_count = _source['zeek'].get('http_server_conns', 0)
            self.http_producer_consumer_ratio_average = _source['zeek'].get('pcr_http_avg', 0)
            self.http_producer_consumer_ratio_max = _source['zeek'].get('pcr_http_max', 0)
            self.http_producer_consumer_ratio_min = _source['zeek'].get('pcr_http_min', 0)
            self.dns_client_connection_count = _source['zeek'].get('dns_client_conns', 0)
            self.dns_server_connection_count = _source['zeek'].get('dns_server_conns', 0)
            self.dns_producer_consumer_ratio_average = _source['zeek'].get('pcr_dns_avg', 0)
            self.dns_producer_consumer_ratio_max = _source['zeek'].get('pcr_dns_max', 0)
            self.dns_producer_consumer_ratio_min = _source['zeek'].get('pcr_dns_min', 0)
            self.ssl_client_connection_count = _source['zeek'].get('ssl_client_conns', 0)
            self.ssl_server_connection_count = _source['zeek'].get('ssl_server_conns', 0)
            self.ssl_producer_consumer_ratio_average = _source['zeek'].get('pcr_ssl_avg', 0)
            self.ssl_producer_consumer_ratio_max = _source['zeek'].get('pcr_ssl_max', 0)
            self.ssl_producer_consumer_ratio_min = _source['zeek'].get('pcr_ssl_min', 0)
            self.rdp_client_connection_count = _source['zeek'].get('rdp_client_conns', 0)
            self.rdp_server_connection_count = _source['zeek'].get('rdp_server_conns', 0)
            self.rdp_producer_consumer_ratio_average = _source['zeek'].get('pcr_rdp_avg', 0)
            self.rdp_producer_consumer_ratio_max = _source['zeek'].get('pcr_rdp_max', 0)
            self.rdp_producer_consumer_ratio_min = _source['zeek'].get('pcr_rdp_min', 0)
        except KeyError:
            raise InvalidIntervalError('Invalid interval record, missing "zeek" section')

    def __str__(self) -> str:
        """
        :return: A JSON representation of the Interval
        """
        return str(vars(self))

    def to_dataframe(self) -> pd.DataFrame:
        """

        :return: DataFrame containng the field headings and single of values
        """
        ignore_vars = ['raw_interval_document']
        headers = [var for var in vars(self) if var not in ignore_vars]
        data = [[getattr(self, header) for header in headers]]
        return pd.DataFrame(data, columns=headers)
