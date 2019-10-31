from typing import Optional
from datetime import datetime


def uid_query(uid: str):
    """
    Generates a Lucene query for retrieving events that match a zeek.uid
    :param uid: A zeek.uid
    :return: A query dictionary
    """
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
                                                    "zeek.uid": "{}".format(uid)
                                                }
                                            }
                                        ],
                                        "minimum_should_match": 1
                                    }
                                },
                                {
                                    "multi_match": {
                                        "type": "best_fields",
                                        "query": "{}".format(uid),
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
    return query


def time_bound_free_text_query(start: datetime, end: datetime, search_filter: Optional[str]):
    """
    Generates a Lucene query for retrieving events between start & end AND an (optional) search_filter
    If search_filter is provided, searches within all searchable fields

    :param start: The start time-frame
    :param end: The end time-frame
    :param search_filter: An optional search filter
    :return: A query dictionary
    """
    start = start.isoformat(sep='T').split('.')[0]
    end = end.isoformat(sep='T').split('.')[0]

    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start,
                                "lte": end
                            }
                        }
                    }
                ],
                "should": [],
                "must_not": []
            }
        },
        "sort": {
            "@timestamp": {"order": "desc"}
        }
    }
    if search_filter:
        query['query']['bool']['filter'] = \
            [
                {
                    "multi_match": {
                        "type": "best_fields",
                        "query": "{}".format(search_filter),
                        "lenient": True
                    }
                }
            ]
    return query


def time_bound_field_query(start: datetime, end: datetime, field: str, value: str):
    """
    Generates a Lucene query for retrieving events between start & end AND  that contain a field which matches
    some value.

    :param start: The start time-frame
    :param end: The end time-frame
    :param field: The field to search in
    :param value: The value to match
    :return: A query dictionary
    """
    start = start.isoformat(sep='T').split('.')[0]
    end = end.isoformat(sep='T').split('.')[0]

    query = \
        {
         "query": {
            "bool": {
              "must": [
                {
                  "range": {
                    "@timestamp": {
                      "format": "strict_date_optional_time",
                      "gte": start,
                      "lte": end
                    }
                  }
                }
              ],
              "filter": [
                {
                  "bool": {
                    "should": [
                      {
                        "match": {
                          field: value
                        }
                      }
                    ],
                    "minimum_should_match": 1
                  }
                }
              ],
              "should": [],
              "must_not": []
            }
          },
         "sort": {
            "@timestamp": {"order": "desc"}
         }
        }
    return query

