import time
import logging

from abc import ABC
from datetime import datetime

import pandas as pd
import elasticsearch

from dynamite_sdk.objects import _queries

from dynamite_sdk import config
from dynamite_sdk.objects import events
from dynamite_sdk.objects import baselines


class InvalidZeekEventError(Exception):
    """
    Thrown when a Zeek event is expected, but a Flow/Suricata event is given
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "Invalid Zeek Event: ".format(message)
        super(InvalidZeekEventError, self).__init__(msg)


index_mappings = {
    'alerts'   :   ('suricata-1.1.0-*', None),
    'baselines':   ('zeek-baselines-*', baselines.Interval),
    'events'   :   ('*event*', events.Event),
    'conn'     :   ('event-flows-*', events.ConnectionEvent),
    'flows'    :   ('event-flows-*', events.ConnectionEvent),
    'dhcp'     :   ('dhcp-events-*', events.DhcpEvent),
    'dns'      :   ('dns-events**', events.DnsEvent),
    'http'     :   ('http-events-*', events.HttpEvent),
    'sip'      :   ('sip-events-*', events.SipEvent),
    'snmp'     :   ('snmp-events-*', events.SnmpEvent),
    'ssh'      :   ('ssh-events-*', events.SshEvent),
}

stderr_logger = logging.getLogger('STDERR')


class Pivot(ABC):

    """
    An abstract interface for pivoting between Zeek events
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

        query = _queries.uid_query(self.uid)
        _hits_raw = self.session.search(body=query, index='*', size=1000)

        matches = _hits_raw['hits']['hits']
        add_event(matches)
        if self.conn_to_network_events:
            self.events = [event for event in events_list if event.event_type != 'conn']
        else:
            self.events = [event for event in events_list if event.event_type == 'conn']
        if self.as_dataframe:
            try:
                self.events = pd.concat([event.to_dataframe() for event in self.events], ignore_index=True)
            except ValueError:
                self.events = pd.DataFrame()


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
        self.results = []
        self.result_count = 0
        self.invalid_result_count = 0
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
        self.result_count = 0
        self.invalid_result_count = 0

        def add_event(raw_events):
            for r_event in raw_events:
                try:
                    event_obj = self.transformation_cls(r_event)
                    if self.as_dataframe:
                        event_obj = event_obj.to_dataframe()
                    events_list.append(event_obj)
                except (events.InvalidEventError, baselines.InvalidIntervalError):
                    self.invalid_result_count += 1
        if isinstance(search_filter, str):
            if ':' in search_filter:
                field, value = search_filter.split(':')
                query = _queries.time_bound_field_query(start, end, field.strip(), value.strip())
            else:
                query = _queries.time_bound_free_text_query(start, end, search_filter)
        else:
            query = _queries.time_bound_free_text_query(start, end, search_filter=None)
        _hits_raw = self.session.search(body=query, index=self.index, size=1000, scroll='5m')
        sid = _hits_raw['_scroll_id']
        matches = _hits_raw['hits']['hits']
        scroll_size = len(matches)
        self.result_count += scroll_size
        add_event(matches)
        while scroll_size > 0:
            _next_hits_raw = self.session.scroll(scroll_id=sid, scroll='5m', request_timeout=60)
            matches = _next_hits_raw['hits']['hits']
            add_event(matches)
            if time.time() - start_time >= self.search_timeout:
                stderr_logger.warning('Exceeded max query time {}s, a smaller search window is suggested'
                                      '...exiting early.'.format(self.search_timeout))
                break
            elif self.result_count >= self.max_search_results:
                stderr_logger.warning('Exceeded max query results {}, a smaller search window is suggested'
                                      '...exiting early'.format(self.max_search_results))
                break
            scroll_size = len(matches)
            self.result_count += scroll_size
        if self.as_dataframe:
            try:
                self.results = pd.concat(events_list, ignore_index=True)
            except ValueError:
                self.results = pd.DataFrame()
        else:
            self.results = events_list

        # Clear old scroll contexts
        self.session.clear_scroll(scroll_id=sid)

        if self.invalid_result_count:
            stderr_logger.warning('{} {} failed to parse.'.format(self.invalid_result_count, self.index))


class ConnectionEventToNetworkEventsPivot(Pivot):
    """
    Provides an interface from a connection event to the corresponding network-event(s) (sub-event)
    """

    def __init__(self, event: events.Event, as_dataframe=False):
        self.uid = None
        if not isinstance(event, events.Event):
            raise events.InvalidEventError('An Zeek Event object was expected, got: {}'.format(type(event)))
        self.uid = event.uid
        if not self.uid:
            raise InvalidZeekEventError('A Zeek event is required for pivot operations, given: {}'.format(
                event.forwarder_type)
            )
        super().__init__(self.uid, conn_to_network_events=True, as_dataframe=as_dataframe)


class NetworkEventToConnectionEventPivot(Pivot):
    """
    Provides an interface from pivoting from some network-event (sub-event) to the corresponding connection event
    """

    def __init__(self, event: events.Event, as_dataframe=False):
        self.uid = event.uid
        if not isinstance(event, events.Event):
            raise events.InvalidEventError('An Zeek Event object was expected, got: {}'.format(type(event)))
        self.uid = event.uid
        if not self.uid:
            raise InvalidZeekEventError('A Zeek event is required for pivot operations, given: {}'.format(
                event.forwarder_type)
            )
        super().__init__(self.uid, conn_to_network_events=False, as_dataframe=as_dataframe)