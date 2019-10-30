import time
import logging

from abc import ABC
from datetime import datetime

import pandas as pd
import elasticsearch

from dynamite_sdk import config
from dynamite_sdk.objects import events


index_mappings = {
    'alerts' : ('suricata-1.1.0-*', None),
    'events': ('-suricata*,*', events.Event),
    'conn'   : ('event-flows-*', events.ConnectionEvent),
    'flows'  : ('event-flows-*', events.ConnectionEvent),
    'dhcp'   : ('dhcp-events-*', events.DhcpEvent),
    'dns'    : ('dns-events**', events.DnsEvent),
    'http'   : ('http-events-*', events.HttpEvent),
    'sip'    : ('sip-events-*', events.SipEvent),
    'snmp'   : ('snmp-events-*', events.SnmpEvent),
    'ssh'    : ('ssh-events-*', events.SshEvent),
}

stderr_logger = logging.getLogger('STDERR')


class Pivot(ABC):

    """
    An abstract interface for pivoting between Zeek logs
    """

    def __init__(self, uid, conn_to_network_events=True, as_dataframe=False):
        """
        :param uid: The unique id "zeek.uid" field
        :param conn_to_network_events: If True, derives Network Event(s) for a given ConnectionEvent;
                                       otherwise derives ConnectionEvent for a given Network Event
        :param as_dataframe: If True, the events instance variable will be a pandas DataFrame rather than a list of
                             events
        """
        auth_config = config['AUTHENTICATION']
        self.uid = uid
        self.conn_to_network_events = conn_to_network_events
        self.as_dataframe = as_dataframe
        self.events = []
        self.event_count = 0
        self.invalid_event_count = 0
        self.session = elasticsearch.Elasticsearch(
            auth_config['elasticsearch_url'],
            http_auth=(auth_config['elasticsearch_user'], auth_config['elasticsearch_password'])
        )

    def execute_pivot(self) -> None:
        """
        Execute the pivot and fetch the corresponding event(s), stores the results in events instance variable

        :return: None
        """
        events_list = []

        def add_event(raw_events):
            for r_event in raw_events:
                try:
                    event_obj = events.Event(r_event)
                    try:
                        index, transformation_cls = index_mappings[event_obj.event_type]
                    except KeyError:
                        transformation_cls = events.Event
                    event_obj = transformation_cls(r_event)
                    events_list.append(event_obj)
                    self.event_count += 1
                except events.InvalidEventError:
                    self.invalid_event_count += 1
        query = {
            "query": {
                "bool": {
                    "filter": [
                        {
                          "bool": {
                            "should": [
                              {
                                "bool": {
                                  "should": [
                                    {
                                      "match": {
                                        "zeek.uid": "{}".format(self.uid)
                                      }
                                    }
                                  ],
                                  "minimum_should_match": 1
                                }
                              },
                              {
                                "multi_match": {
                                  "type": "best_fields",
                                  "query": "{}".format(self.uid),
                                  "lenient": True
                                }
                              }
                            ],
                            "minimum_should_match": 1
                          }
                        }
                      ]
                }
            },
            "sort": {
                "@timestamp": {"order": "desc"}
            }
        }
        _hits_raw = self.session.search(body=query, index='*', size=1000)

        matches = _hits_raw['hits']['hits']
        add_event(matches)
        if self.conn_to_network_events:
            self.events = [event for event in events_list if event.event_type != 'conn']
        else:
            self.events = [event for event in events_list if event.event_type == 'conn']
        if self.as_dataframe:
            self.events = pd.concat([event.to_dataframe() for event in self.events])


class Search:

    def __init__(self, index, as_dataframe=False):
        """
        :param index: The corresponding elasticsearch index or log name to search
        :param as_dataframe: If True, the events instance variable will be a pandas DataFrame rather than a list of
                             events
        """
        try:
            self.index, self.transformation_cls = index_mappings[index]
        except KeyError:
            self.index = index
            self.transformation_cls = events.Event
        auth_config = config['AUTHENTICATION']
        self.as_dataframe = as_dataframe
        self.events = []
        self.event_count = 0
        self.invalid_event_count = 0
        self.search_timeout = int(config['SEARCH']['timeout'])
        self.max_search_results = int(config['SEARCH']['max_results'])
        self.session = elasticsearch.Elasticsearch(
            auth_config['elasticsearch_url'],
            http_auth=(auth_config['elasticsearch_user'], auth_config['elasticsearch_password'])
        )

    def execute_query(self, start: datetime, end: datetime, search_filter=None):
        """
        Executes a search query, stores the results in events instance variable

        :param start: The start time-frame
        :param end: The end time-frame
        :param search_filter: An optional search filter
        :return: None
        """
        events_list = []
        start_time = time.time()
        self.event_count = 0
        self.invalid_event_count = 0

        def add_event(raw_events):
            for r_event in raw_events:
                try:
                    event_obj = self.transformation_cls(r_event)
                    if self.as_dataframe:
                        event_obj = event_obj.to_dataframe()
                    events_list.append(event_obj)
                except events.InvalidEventError:
                    self.invalid_event_count += 1

        if search_filter:
            search_filter = 'AND {}'.format(search_filter)
        else:
            search_filter = ''
        start = start.isoformat(sep='T').split('.')[0]
        end = end.isoformat(sep='T').split('.')[0]

        query = {
            "query": {
                "query_string": {
                    "default_field": "_all",
                    "query": '@timestamp:[{} TO {}] {}'.format(start, end, search_filter)
                }
            },
            "sort": {
                "@timestamp": {"order": "desc"}
            }
        }
        _hits_raw = self.session.search(body=query, index=self.index, size=1000, scroll='5m')
        sid = _hits_raw['_scroll_id']
        matches = _hits_raw['hits']['hits']
        scroll_size = len(matches)
        self.event_count += scroll_size
        add_event(matches)
        while scroll_size > 0:
            _next_hits_raw = self.session.scroll(scroll_id=sid, scroll='5m', request_timeout=60)
            matches = _next_hits_raw['hits']['hits']
            add_event(matches)
            if time.time() - start_time >= self.search_timeout:
                stderr_logger.warning('Exceeded max query time {}s, a smaller search window is suggested'
                                      '...exiting early.'.format(self.search_timeout))
                break
            elif self.event_count >= self.max_search_results:
                stderr_logger.warning('Exceeded max query results {}, a smaller search window is suggested'
                                      '...exiting early'.format(self.max_search_results))
                break
            scroll_size = len(matches)
            self.event_count += scroll_size
        if self.as_dataframe:
            self.events = pd.concat(events_list)
        else:
            self.events = events_list

        if self.invalid_event_count:
            stderr_logger.warning('{} {} failed to parse.'.format(self.invalid_event_count, self.index))


class ConnectionEventToNetworkEventsPivot(Pivot):
    """
    Provides an interface from a connection event to the corresponding network-event(s) (sub-event)
    """

    def __init__(self, uid, as_dataframe=False):
        self.uid = uid
        super().__init__(uid, conn_to_network_events=True, as_dataframe=as_dataframe)


class NetworkEventToConnectionEventPivot(Pivot):
    """
    Provides an interface from pivoting from some network-event (sub-event) to the corresponding connection event
    """

    def __init__(self, uid, as_dataframe=False):
        self.uid = uid
        super().__init__(uid, conn_to_network_events=False, as_dataframe=as_dataframe)



from datetime import timedelta

start = datetime.now() - timedelta(hours=10)
end = datetime.now()

search = Search('conn', as_dataframe=True)
search.execute_query(start, end, search_filter="flow.client_addr: 89.248.172.16")
print(search.events)
