#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2012 Matt Martz
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import csv
import datetime
import errno
import math
import os
import platform
import re
import signal
import socket
import sys
import threading
import timeit
import xml.parsers.expat

try:
    import gzip
    GZIP_BASE = gzip.GzipFile
except ImportError:
    gzip = None
    GZIP_BASE = object

__version__ = '2.1.4b1'


class FakeShutdownEvent(object):
    """Class to fake a threading.Event.isSet so that home of this module
    are not required to register their own threading.Event()
    """

    @staticmethod
    def isSet():
        "Dummy method to always return false"""
        return False

    is_set = isSet

# Some global variables we use
DEBUG = False
_GLOBAL_DEFAULT_TIMEOUT = object()
PY25PLUS = sys.version_info[:2] >= (2, 5)
PY26PLUS = sys.version_info[:2] >= (2, 6)
PY32PLUS = sys.version_info[:2] >= (3, 2)
PY310PLUS = sys.version_info[:2] >= (3, 10)

# Begin import game to handle Python 2 and Python 3
try:
    import json
except ImportError:
    try:
        import simplejson as json
    except ImportError:
        json = None

try:
    import xml.etree.ElementTree as ET
    try:
        from xml.etree.ElementTree import _Element as ET_Element
    except ImportError:
        pass
except ImportError:
    from xml.dom import minidom as DOM
    from xml.parsers.expat import ExpatError
    ET = None

try:
    from urllib2 import (urlopen, Request, HTTPError, URLError,
                         AbstractHTTPHandler, ProxyHandler,
                         HTTPDefaultErrorHandler, HTTPRedirectHandler,
                         HTTPErrorProcessor, OpenerDirector)
except ImportError:
    from urllib.request import (urlopen, Request, HTTPError, URLError,
                                AbstractHTTPHandler, ProxyHandler,
                                HTTPDefaultErrorHandler, HTTPRedirectHandler,
                                HTTPErrorProcessor, OpenerDirector)

try:
    from httplib import HTTPConnection, BadStatusLine
except ImportError:
    from http.client import HTTPConnection, BadStatusLine

try:
    from httplib import HTTPSConnection
except ImportError:
    try:
        from http.client import HTTPSConnection
    except ImportError:
        HTTPSConnection = None

try:
    from httplib import FakeSocket
except ImportError:
    FakeSocket = None

try:
    from Queue import Queue
except ImportError:
    from queue import Queue

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

try:
    from urlparse import parse_qs
except ImportError:
    try:
        from urllib.parse import parse_qs
    except ImportError:
        from cgi import parse_qs

try:
    from hashlib import md5
except ImportError:
    from md5 import md5

try:
    from argparse import ArgumentParser as ArgParser
    from argparse import SUPPRESS as ARG_SUPPRESS
    PARSER_TYPE_INT = int
    PARSER_TYPE_STR = str
    PARSER_TYPE_FLOAT = float
except ImportError:
    from optparse import OptionParser as ArgParser
    from optparse import SUPPRESS_HELP as ARG_SUPPRESS
    PARSER_TYPE_INT = 'int'
    PARSER_TYPE_STR = 'string'
    PARSER_TYPE_FLOAT = 'float'

try:
    from cStringIO import StringIO
    BytesIO = None
except ImportError:
    try:
        from StringIO import StringIO
        BytesIO = None
    except ImportError:
        from io import StringIO, BytesIO

try:
    import __builtin__
except ImportError:
    import builtins
    from io import TextIOWrapper, FileIO

    class _Py3Utf8Output(TextIOWrapper):
        """UTF-8 encoded wrapper around stdout for py3, to override
        ASCII stdout
        """
        def __init__(self, f, **kwargs):
            buf = FileIO(f.fileno(), 'w')
            super(_Py3Utf8Output, self).__init__(
                buf,
                encoding='utf8',
                errors='strict'
            )

        def write(self, s):
            super(_Py3Utf8Output, self).write(s)
            self.flush()

    _py3_print = getattr(builtins, 'print')
    try:
        _py3_utf8_stdout = _Py3Utf8Output(sys.stdout)
        _py3_utf8_stderr = _Py3Utf8Output(sys.stderr)
    except OSError:
  # sys.stdout/sys.stderr is not a compatible stdout/stderr object
        # just use it and hope things go ok
        _py3_utf8_stdout = sys.stdout
        _py3_utf8_stderr = sys.stderr

    def to_utf8(v):
        """No-op encode to utf-8 for py3"""
        return v

    def print_(*args, **kwargs):
        """Wrapper function for py3 to print, with a utf-8 encoded stdout"""
        if kwargs.get('file') == sys.stderr:
            kwargs['file'] = _py3_utf8_stderr
        else:
            kwargs['file'] = kwargs.get('file', _py3_utf8_stdout)
        _py3_print(*args, **kwargs)
else:
    del __builtin__

    def to_utf8(v):
        """Encode value to utf-8 if possible for py2"""
        try:
            return v.encode('utf8', 'strict')
        except AttributeError:
            return v

    def print_(*args, **kwargs):
        """The new-style print function for Python 2.4 and 2.5.

        Taken from https://pypi.python.org/pypi/six/

        Modified to set encoding to UTF-8 always, and to flush after write
        """
        fp = kwargs.pop("file", sys.stdout)
        if fp is None:
            return

        def write(data):
            if not isinstance(data, basestring):
                data = str(data)
            # If the file has an encoding, encode unicode with it.
            encoding = 'utf8'  # Always trust UTF-8 for output
            if (isinstance(fp, file) and
                    isinstance(data, unicode) and
                    encoding is not None):
                errors = getattr(fp, "errors", None)
                if errors is None:
                    errors = "strict"
                data = data.encode(encoding, errors)
            fp.write(data)
            fp.flush()
        want_unicode = False
        sep = kwargs.pop("sep", None)
        if sep is not None:
            if isinstance(sep, unicode):
                want_unicode = True
            elif not isinstance(sep, str):
                raise TypeError("sep must be None or a string")
        end = kwargs.pop("end", None)
        if end is not None:
            if isinstance(end, unicode):
                want_unicode = True
            elif not isinstance(end, str):
                raise TypeError("end must be None or a string")
        if kwargs:
            raise TypeError("invalid keyword arguments to print()")
        if not want_unicode:
            for arg in args:
                if isinstance(arg, unicode):
                    want_unicode = True
                    break
        if want_unicode:
            newline = unicode("\n")
            space = unicode(" ")
        else:
            newline = "\n"
            space = " "
        if sep is None:
            sep = space
        if end is None:
            end = newline
        for i, arg in enumerate(args):
            if i:
                write(sep)
            write(arg)
        write(end)
# Exception "constants" to support Python 2 through Python 3
try:
    import ssl
    try:
        CERT_ERROR = (ssl.CertificateError,)
    except AttributeError:
        CERT_ERROR = tuple()

    HTTP_ERRORS = (
        (HTTPError, URLError, socket.error, ssl.SSLError, BadStatusLine) +
        CERT_ERROR
    )
except ImportError:
    ssl = None
    HTTP_ERRORS = (HTTPError, URLError, socket.error, BadStatusLine)

if PY32PLUS:
    etree_iter = ET.Element.iter
elif PY25PLUS:
    etree_iter = ET_Element.getiterator

if PY26PLUS:
    thread_is_alive = threading.Thread.is_alive
else:
    thread_is_alive = threading.Thread.isAlive


def event_is_set(event):
    try:
        return event.is_set()
    except AttributeError:
        return event.isSet()


class SpeedtestException(Exception):
    """Base exception for this module"""


class SpeedtestCLIError(SpeedtestException):
    """Generic exception for raising errors during CLI operation"""


class SpeedtestHTTPError(SpeedtestException):
    """Base HTTP exception for this module"""


class SpeedtestConfigError(SpeedtestException):
    """Configuration XML is invalid"""


class SpeedtestServersError(SpeedtestException):
    """Servers XML is invalid"""


class ConfigRetrievalError(SpeedtestHTTPError):
    """Could not retrieve config.php"""


class ServersRetrievalError(SpeedtestHTTPError):
    """Could not retrieve speedtest-servers.php"""


class InvalidServerIDType(SpeedtestException):
    """Server ID used for filtering was not an integer"""


class NoMatchedServers(SpeedtestException):
    """No servers matched when filtering"""


class SpeedtestMiniConnectFailure(SpeedtestException):
    """Could not connect to the provided speedtest mini server"""


class InvalidSpeedtestMiniServer(SpeedtestException):
    """Server provided as a speedtest mini server does not actually appear
    to be a speedtest mini server
    """


class ShareResultsConnectFailure(SpeedtestException):
    """Could not connect to speedtest.net API to POST results"""


class ShareResultsSubmitFailure(SpeedtestException):
    """Unable to successfully POST results to speedtest.net API after
    connection
    """


class SpeedtestUploadTimeout(SpeedtestException):
    """testlength configuration reached during upload
    Used to ensure the upload halts when no additional data should be sent
    """


class SpeedtestBestServerFailure(SpeedtestException):
    """Unable to determine best server"""


class SpeedtestMissingBestServer(SpeedtestException):
    """get_best_server not called or not able to determine best server"""


def create_connection(address, timeout=_GLOBAL_DEFAULT_TIMEOUT,
                      source_address=None):
    """Connect to *address* and return the socket object.
Convenience function.  Connect to *address* (a 2-tuple ``(host,
    port)``) and return the socket object.  Passing the optional
    *timeout* parameter will set the timeout on the socket instance
    before attempting to connect.  If no *timeout* is supplied, the
    global default timeout setting returned by :fun`getdefaulttimeout`
    is used.  If *source_address* is set it must be a tuple of (host, port)
    for the socket to bind as a source address before making the connection.
    An host of '' or port 0 tells the OS to use the default.

    Largely vendored from Python 2.7, modified to work with Python 2.4
    """

    host, port = address
    err = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            if timeout is not _GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(float(timeout))
            if source_address:
                sock.bind(source_address)
            sock.connect(sa)
            return sock

        except socket.error:
            err = get_exception()
            if sock is not None:
                sock.close()

    if err is not None:
        raise err
    else:
        raise socket.error("getaddrinfo returns an empty list")


class SpeedtestHTTPConnection(HTTPConnection):
    """Custom HTTPConnection to support source_address across
    Python 2.4 - Python 3
    """
    def __init__(self, *args, **kwargs):
        source_address = kwargs.pop('source_address', None)
        timeout = kwargs.pop('timeout', 10)

        self._tunnel_host = None

        HTTPConnection.__init__(self, *args, **kwargs)

        self.source_address = source_address
        self.timeout = timeout

    def connect(self):
        """Connect to the host and port specified in __init__."""
        try:
            self.sock = socket.create_connection(
                (self.host, self.port),
                self.timeout,
                self.source_address
            )
        except (AttributeError, TypeError):
            self.sock = create_connection(
                (self.host, self.port),
                self.timeout,
                self.source_address
            )

        if self._tunnel_host:
            self._tunnel()
if HTTPSConnection:
    class SpeedtestHTTPSConnection(HTTPSConnection):
        """Custom HTTPSConnection to support source_address across
        Python 2.4 - Python 3
        """
        default_port = 443

        def __init__(self, *args, **kwargs):
            source_address = kwargs.pop('source_address', None)
            timeout = kwargs.pop('timeout', 10)

            self._tunnel_host = None

            HTTPSConnection.__init__(self, *args, **kwargs)

            self.timeout = timeout
            self.source_address = source_address

        def connect(self):
            "Connect to a host on a given (SSL) port."
            try:
                self.sock = socket.create_connection(
                    (self.host, self.port),
                    self.timeout,
                    self.source_address
                )
            except (AttributeError, TypeError):
                self.sock = create_connection(
                    (self.host, self.port),
                    self.timeout,
                    self.source_address
                )

            if self._tunnel_host:
                self._tunnel()

            if ssl:
                try:
                    kwargs = {}
                    if hasattr(ssl, 'SSLContext'):
                        if self._tunnel_host:
                            kwargs['server_hostname'] = self._tunnel_host
                        else:
                            kwargs['server_hostname'] = self.host
                    self.sock = self._context.wrap_socket(self.sock, **kwargs)
                except AttributeError:
                    self.sock = ssl.wrap_socket(self.sock)
                    try:
                        self.sock.server_hostname = self.host
                    except AttributeError:
                        pass
            elif FakeSocket:
                # Python 2.4/2.5 support
                try:
                    self.sock = FakeSocket(self.sock, socket.ssl(self.sock))
                except AttributeError:
                    raise SpeedtestException(
                        'This version of Python does not support HTTPS/SSL '
                        'functionality'
                    )
            else:
                raise SpeedtestException(
                    'This version of Python does not support HTTPS/SSL '
                    'functionality'
                )
def _build_connection(connection, source_address, timeout, context=None):
    """Cross Python 2.4 - Python 3 callable to build an ``HTTPConnection`` or
    ``HTTPSConnection`` with the args we need

    Called from ``http(s)_open`` methods of ``SpeedtestHTTPHandler`` or
    ``SpeedtestHTTPSHandler``
    """
    def inner(host, **kwargs):
        kwargs.update({
            'source_address': source_address,
            'timeout': timeout
        })
        if context:
            kwargs['context'] = context
        return connection(host, **kwargs)
    return inner


class SpeedtestHTTPHandler(AbstractHTTPHandler):
    """Custom ``HTTPHandler`` that can build a ``HTTPConnection`` with the
    args we need for ``source_address`` and ``timeout``
    """
    def __init__(self, debuglevel=0, source_address=None, timeout=10):
        AbstractHTTPHandler.__init__(self, debuglevel)
        self.source_address = source_address
        self.timeout = timeout

    def http_open(self, req):
        return self.do_open(
            _build_connection(
                SpeedtestHTTPConnection,
                self.source_address,
                self.timeout
            ),
            req
        )

    http_request = AbstractHTTPHandler.do_request_


class SpeedtestHTTPSHandler(AbstractHTTPHandler):
    """Custom ``HTTPSHandler`` that can build a ``HTTPSConnection`` with the
    args we need for ``source_address`` and ``timeout``
    """
    def __init__(self, debuglevel=0, context=None, source_address=None,
                 timeout=10):
        AbstractHTTPHandler.__init__(self, debuglevel)
        self._context = context
        self.source_address = source_address
        self.timeout = timeout

    def https_open(self, req):
        return self.do_open(
            _build_connection(
                SpeedtestHTTPSConnection,
                self.source_address,
                self.timeout,
                context=self._context,
            ),
            req
        )

    https_request = AbstractHTTPHandler.do_request_


def build_opener(source_address=None, timeout=10):
    """Function similar to ``urllib2.build_opener`` that will build
    an ``OpenerDirector`` with the explicit handlers we want,
    ``source_address`` for binding, ``timeout`` and our custom
    `User-Agent`
    """

    printer('Timeout set to %d' % timeout, debug=True)
if source_address:
        source_address_tuple = (source_address, 0)
        printer('Binding to source address: %r' % (source_address_tuple,),
                debug=True)
    else:
        source_address_tuple = None

    handlers = [
        ProxyHandler(),
        SpeedtestHTTPHandler(source_address=source_address_tuple,
                             timeout=timeout),
        SpeedtestHTTPSHandler(source_address=source_address_tuple,
                              timeout=timeout),
        HTTPDefaultErrorHandler(),
        HTTPRedirectHandler(),
        HTTPErrorProcessor()
    ]

    opener = OpenerDirector()
    opener.addheaders = [('User-agent', build_user_agent())]

    for handler in handlers:
        opener.add_handler(handler)

    return opener


class GzipDecodedResponse(GZIP_BASE):
    """A file-like object to decode a response encoded with the gzip
    method, as described in RFC 1952.

    Largely copied from ``xmlrpclib``/``xmlrpc.client`` and modified
    to work for py2.4-py3
    """
    def __init__(self, response):
        # response doesn't support tell() and read(), required by
        # GzipFile
        if not gzip:
            raise SpeedtestHTTPError('HTTP response body is gzip encoded, '
                                     'but gzip support is not available')
        IO = BytesIO or StringIO
        self.io = IO()
        while 1:
            try:
                configxml_list.append(stream.read(1024))
            except (OSError, EOFError):
                raise ConfigRetrievalError(get_exception())
            if len(configxml_list[-1]) == 0:
                break
        stream.close()
        uh.close()

        if int(uh.code) != 200:
            return None

        configxml = ''.encode().join(configxml_list)

        printer('Config XML:\n%s' % configxml, debug=True)

        try:
            try:
                root = ET.fromstring(configxml)
            except ET.ParseError:
                e = get_exception()
                raise SpeedtestConfigError(
                    'Malformed speedtest.net configuration: %s' % e
                )
            server_config = root.find('server-config').attrib
            download = root.find('download').attrib
            upload = root.find('upload').attrib
            # times = root.find('times').attrib
            client = root.find('client').attrib
except AttributeError:
            try:
                root = DOM.parseString(configxml)
            except ExpatError:
                e = get_exception()
                raise SpeedtestConfigError(
                    'Malformed speedtest.net configuration: %s' % e
                )
            server_config = get_attributes_by_tag_name(root, 'server-config')
            download = get_attributes_by_tag_name(root, 'download')
            upload = get_attributes_by_tag_name(root, 'upload')
            # times = get_attributes_by_tag_name(root, 'times')
            client = get_attributes_by_tag_name(root, 'client')

        ignore_servers = [
            int(i) for i in server_config['ignoreids'].split(',') if i
        ]

        ratio = int(upload['ratio'])
        upload_max = int(upload['maxchunkcount'])
        up_sizes = [32768, 65536, 131072, 262144, 524288, 1048576, 7340032]
        sizes = {
            'upload': up_sizes[ratio - 1:],
            'download': [350, 500, 750, 1000, 1500, 2000, 2500,
                         3000, 3500, 4000]
        }

        size_count = len(sizes['upload'])

        upload_count = int(math.ceil(upload_max / size_count))

        counts = {
            'upload': upload_count,
            'download': int(download['threadsperurl'])
        }

        threads = {
            'upload': int(upload['threads']),
            'download': int(server_config['threadcount']) * 2
        }

        length = {
            'upload': int(upload['testlength']),
            'download': int(download['testlength'])
        }

        self.config.update({
            'client': client,
            'ignore_servers': ignore_servers,
            'sizes': sizes,
            'counts': counts,
            'threads': threads,
            'length': length,
            'upload_max': upload_count * size_count
        })

        try:
            self.lat_lon = (float(client['lat']), float(client['lon']))
        except ValueError:
            raise SpeedtestConfigError(
                'Unknown location: lat=%r lon=%r' %
                (client.get('lat'), client.get('lon'))
            )

        printer('Config:\n%r' % self.config, debug=True)

        return self.config

    def get_servers(self, servers=None, exclude=None):
        """Retrieve a the list of speedtest.net servers, optionally filtered
        to servers matching those specified in the ``servers`` argument
        """
        if servers is None:
            servers = []

        if exclude is None:
            exclude = []

        self.servers.clear()

        for server_list in (servers, exclude):
            for i, s in enumerate(server_list):
                try:
                    server_list[i] = int(s)
                except ValueError:
                    raise InvalidServerIDType(
                        '%s is an invalid server type, must be int' % s
                    )
urls = [
            '://www.speedtest.net/speedtest-servers-static.php',
            'http://c.speedtest.net/speedtest-servers-static.php',
            '://www.speedtest.net/speedtest-servers.php',
            'http://c.speedtest.net/speedtest-servers.php',
        ]

        headers = {}
        if gzip:
            headers['Accept-Encoding'] = 'gzip'

        errors = []
        for url in urls:
            try:
                request = build_request(
                    '%s?threads=%s' % (url,
                                       self.config['threads']['download']),
                    headers=headers,
                    secure=self._secure
                )
                uh, e = catch_request(request, opener=self._opener)
                if e:
                    errors.append('%s' % e)
                    raise ServersRetrievalError()

                stream = get_response_stream(uh)

                serversxml_list = []
                while 1:
                    try:
                        serversxml_list.append(stream.read(1024))
                    except (OSError, EOFError):
                        raise ServersRetrievalError(get_exception())
                    if len(serversxml_list[-1]) == 0:
                        break

                stream.close()
                uh.close()

                if int(uh.code) != 200:
                    raise ServersRetrievalError()

                serversxml = ''.encode().join(serversxml_list)

                printer('Servers XML:\n%s' % serversxml, debug=True)

                try:
                    try:
                        try:
                            root = ET.fromstring(serversxml)
                        except ET.ParseError:
                            e = get_exception()
                            raise SpeedtestServersError(
                                'Malformed speedtest.net server list: %s' % e
                            )
                        elements = etree_iter(root, 'server')
                    except AttributeError:
                        try:
                            root = DOM.parseString(serversxml)
                        except ExpatError:
                            e = get_exception()
                            raise SpeedtestServersError(
                                'Malformed speedtest.net server list: %s' % e
                            )
                        elements = root.getElementsByTagName('server')
                except (SyntaxError, xml.parsers.expat.ExpatError):
                    raise ServersRetrievalError()

                for server in elements:
                    try:
                        attrib = server.attrib
                    except AttributeError:
                        attrib = dict(list(server.attributes.items()))

                    if servers and int(attrib.get('id')) not in servers:
                        continue

                    if (int(attrib.get('id')) in self.config['ignore_servers']
                            or int(attrib.get('id')) in exclude):
                        continue

                    try:
                        d = distance(self.lat_lon,
                                     (float(attrib.get('lat')),
                                      float(attrib.get('lon'))))
                    except Exception:
                        continue

                    attrib['d'] = d

                    try:
                        self.servers[d].append(attrib)
                    except KeyError:
                        self.servers[d] = [attrib]

                break
except ServersRetrievalError:
                continue

        if (servers or exclude) and not self.servers:
            raise NoMatchedServers()

        return self.servers

    def set_mini_server(self, server):
        """Instead of querying for a list of servers, set a link to a
        speedtest mini server
        """

        urlparts = urlparse(server)

        name, ext = os.path.splitext(urlparts[2])
        if ext:
            url = os.path.dirname(server)
        else:
            url = server

        request = build_request(url)
        uh, e = catch_request(request, opener=self._opener)
        if e:
            raise SpeedtestMiniConnectFailure('Failed to connect to %s' %
                                              server)
        else:
            text = uh.read()
            uh.close()

        extension = re.findall('upload_?[Ee]xtension: "([^"]+)"',
                               text.decode())
        if not extension:
            for ext in ['php', 'asp', 'aspx', 'jsp']:
                try:
                    f = self._opener.open(
                        '%s/speedtest/upload.%s' % (url, ext)
                    )
                except Exception:
                    pass
                else:
                    data = f.read().strip().decode()
                    if (f.code == 200 and
                            len(data.splitlines()) == 1 and
                            re.match('size=[0-9]', data)):
                        extension = [ext]
                        break
        if not urlparts or not extension:
            raise InvalidSpeedtestMiniServer('Invalid Speedtest Mini Server: '
                                             '%s' % server)

        self.servers = [{
            'sponsor': 'Speedtest Mini',
            'name': urlparts[1],
            'd': 0,
            'url': '%s/speedtest/upload.%s' % (url.rstrip('/'), extension[0]),
            'latency': 0,
            'id': 0
        }]

        return self.servers

    def get_closest_servers(self, limit=5):
        """Limit servers to the closest speedtest.net servers based on
        geographic distance
        """

        if not self.servers:
            self.get_servers()

        for d in sorted(self.servers.keys()):
            for s in self.servers[d]:
                self.closest.append(s)
                if len(self.closest) == limit:
                    break
            else:
                continue
            break

        printer('Closest Servers:\n%r' % self.closest, debug=True)
        return self.closest

    def get_best_server(self, servers=None):
        """Perform a speedtest.net "ping" to determine which speedtest.net
        server has the lowest latency
        """

        if not servers:
            if not self.closest:
                servers = self.get_closest_servers()
            servers = self.closest

        if self._source_address:
            source_address_tuple = (self._source_address, 0)
        else:
            source_address_tuple = None

        user_agent = build_user_agent()

        results = {}
        for server in servers:
            cum = []
            url = os.path.dirname(server['url'])
            stamp = int(timeit.time.time() * 1000)
            latency_url = '%s/latency.txt?x=%s' % (url, stamp)
            for i in range(0, 3):
                this_latency_url = '%s.%s' % (latency_url, i)
                printer('%s %s' % ('GET', this_latency_url),
                        debug=True)
                urlparts = urlparse(latency_url)
                try:
                    if urlparts[0] == 'https':
                        h = SpeedtestHTTPSConnection(
                            urlparts[1],
                            source_address=source_address_tuple
                        )
                    else:
                        h = SpeedtestHTTPConnection(
                            urlparts[1],
                            source_address=source_address_tuple
                        )
                    headers = {'User-Agent': user_agent}
                    path = '%s?%s' % (urlparts[2], urlparts[4])
                    start = timeit.default_timer()
                    h.request("GET", path, headers=headers)
                    r = h.getresponse()
                    total = (timeit.default_timer() - start)
                except HTTP_ERRORS:
                    e = get_exception()
                    printer('ERROR: %r' % e, debug=True)
                    cum.append(3600)
                    continue

                text = r.read(9)
                if int(r.status) == 200 and text == 'test=test'.encode():
                    cum.append(total)
                else:
                    cum.append(3600)
                h.close()

            avg = round((sum(cum) / 6) * 1000.0, 3)
            results[avg] = server

        try:
            fastest = sorted(results.keys())[0]
        except IndexError:
            raise SpeedtestBestServerFailure('Unable to connect to servers to '
                                             'test latency.')
        best = results[fastest]
        best['latency'] = fastest

        self.results.ping = fastest
        self.results.server = best

        self._best.update(best)
        printer('Best Server:\n%r' % best, debug=True)
        return best

    def download(self, callback=do_nothing, threads=None):
        """Test download speed against speedtest.net

        A ``threads`` value of ``None`` will fall back to those dictated
        by the speedtest.net configuration
        """
urls = []
        for size in self.config['sizes']['download']:
            for _ in range(0, self.config['counts']['download']):
                urls.append('%s/random%sx%s.jpg' %
                            (os.path.dirname(self.best['url']), size, size))

        request_count = len(urls)
        requests = []
        for i, url in enumerate(urls):
            requests.append(
                build_request(url, bump=i, secure=self._secure)
            )

        max_threads = threads or self.config['threads']['download']
        in_flight = {'threads': 0}

        def producer(q, requests, request_count):
            for i, request in enumerate(requests):
                thread = HTTPDownloader(
                    i,
                    request,
                    start,
                    self.config['length']['download'],
                    opener=self._opener,
                    shutdown_event=self._shutdown_event
                )
                while in_flight['threads'] >= max_threads:
                    timeit.time.sleep(0.001)
                thread.start()
                q.put(thread, True)
                in_flight['threads'] += 1
                callback(i, request_count, start=True)

        finished = []

        def consumer(q, request_count):
            _is_alive = thread_is_alive
            while len(finished) < request_count:
                thread = q.get(True)
                while _is_alive(thread):
                    thread.join(timeout=0.001)
                in_flight['threads'] -= 1
                finished.append(sum(thread.result))
                callback(thread.i, request_count, end=True)

        q = Queue(max_threads)
        prod_thread = threading.Thread(target=producer,
                                       args=(q, requests, request_count))
        cons_thread = threading.Thread(target=consumer,
                                       args=(q, request_count))
        start = timeit.default_timer()
        prod_thread.start()
        cons_thread.start()
        _is_alive = thread_is_alive
        while _is_alive(prod_thread):
            prod_thread.join(timeout=0.001)
        while _is_alive(cons_thread):
            cons_thread.join(timeout=0.001)

        stop = timeit.default_timer()
        self.results.bytes_received = sum(finished)
        self.results.download = (
            (self.results.bytes_received / (stop - start)) * 8.0
        )
        if self.results.download > 100000:
            self.config['threads']['upload'] = 8
        return self.results.download

    def upload(self, callback=do_nothing, pre_allocate=True, threads=None):
        """Test upload speed against speedtest.net

        A ``threads`` value of ``None`` will fall back to those dictated
        by the speedtest.net configuration
        """

        sizes = []

        for size in self.config['sizes']['upload']:
            for _ in range(0, self.config['counts']['upload']):
                sizes.append(size)

        # request_count = len(sizes)
        request_count = self.config['upload_max']

        requests = []
        for i, size in enumerate(sizes):
            # We set ``0`` for ``start`` and handle setting the actual
            # ``start`` in ``HTTPUploader`` to get better measurements
            data = HTTPUploaderData(
                size,
                0,
                self.config['length']['upload'],
                shutdown_event=self._shutdown_event
            )
            if pre_allocate:
                data.pre_allocate()

            headers = {'Content-length': size}
            requests.append(
                (
                    build_request(self.best['url'], data, secure=self._secure,
                                  headers=headers),
                    size
                )
            )

        max_threads = threads or self.config['threads']['upload']
        in_flight = {'threads': 0}

        def producer(q, requests, request_count):
            for i, request in enumerate(requests[:request_count]):
                thread = HTTPUploader(
                    i,
                    request[0],
                    start,
                    request[1],
                    self.config['length']['upload'],
                    opener=self._opener,
                    shutdown_event=self._shutdown_event
                )
                while in_flight['threads'] >= max_threads:
                    timeit.time.sleep(0.001)
                thread.start()
                q.put(thread, True)
                in_flight['threads'] += 1
                callback(i, request_count, start=True)

        finished = []
def consumer(q, request_count):
            _is_alive = thread_is_alive
            while len(finished) < request_count:
                thread = q.get(True)
                while _is_alive(thread):
                    thread.join(timeout=0.001)
                in_flight['threads'] -= 1
                finished.append(thread.result)
                callback(thread.i, request_count, end=True)

        q = Queue(threads or self.config['threads']['upload'])
        prod_thread = threading.Thread(target=producer,
                                       args=(q, requests, request_count))
        cons_thread = threading.Thread(target=consumer,
                                       args=(q, request_count))
        start = timeit.default_timer()
        prod_thread.start()
        cons_thread.start()
        _is_alive = thread_is_alive
        while _is_alive(prod_thread):
            prod_thread.join(timeout=0.1)
        while _is_alive(cons_thread):
            cons_thread.join(timeout=0.1)

        stop = timeit.default_timer()
        self.results.bytes_sent = sum(finished)
        self.results.upload = (
            (self.results.bytes_sent / (stop - start)) * 8.0
        )
        return self.results.upload


def ctrl_c(shutdown_event):
    """Catch Ctrl-C key sequence and set a SHUTDOWN_EVENT for our threaded
    operations
    """
    def inner(signum, frame):
        shutdown_event.set()
        printer('\nMembatalkan...', error=True)
        sys.exit(0)
    return inner


def version():
    """Print the version"""

    printer('speedtest-cli %s' % __version__)
    printer('Python %s' % sys.version.replace('\n', ''))
    sys.exit(0)


def csv_header(delimiter=','):
    """Print the CSV Headers"""

    printer(SpeedtestResults.csv_header(delimiter=delimiter))
    sys.exit(0)


def parse_args():
    """Function to handle building and parsing of command line arguments"""
    description = (
        'Command line interface for testing internet bandwidth using '
        'speedtest.net.\n'
        '------------------------------------------------------------'
        '--------------\n'
        'https://github.com/sivel/speedtest-cli')

    parser = ArgParser(description=description)
    # Give optparse.OptionParser an `add_argument` method for
    # compatibility with argparse.ArgumentParser
    try:
        parser.add_argument = parser.add_option
    except AttributeError:
        pass
    parser.add_argument('--no-download', dest='download', default=True,
                        action='store_const', const=False,
                        help='Jangan lakukan tes unduh')
    parser.add_argument('--no-upload', dest='upload', default=True,
                        action='store_const', const=False,
                        help='Jangan lakukan tes unggah')
    parser.add_argument('--single', default=False, action='store_true',
                        help='Hanya gunakan satu koneksi alih-alih '
                             'banyak. Ini mensimulasikan transfer file '
                             'yang umum.')
    parser.add_argument('--bytes', dest='units', action='store_const',
                        const=('byte', 8), default=('bit', 1),
                        help='Tampilkan nilai dalam byte alih-alih bit. Tidak '
                             'mempengaruhi gambar yang dihasilkan oleh --share, '
                             'maupun output dari --json atau --csv')
    parser.add_argument('--share', action='store_true',
                        help='Hasilkan dan berikan URL ke gambar hasil '
                             'speedtest.net, tidak ditampilkan dengan --csv')
    parser.add_argument('--simple', action='store_true', default=False,
                        help='Sembunyikan output verbose, hanya tampilkan '
                             'informasi dasar')
    parser.add_argument('--csv', action='store_true', default=False,
                        help='Sembunyikan output verbose, hanya tampilkan '
                             'informasi dasar dalam format CSV. Kecepatan '
                             'dalam bit/s dan tidak terpengaruh oleh --bytes')
    parser.add_argument('--csv-delimiter', default=',', type=PARSER_TYPE_STR,
                        help='Pemisah karakter tunggal untuk digunakan dalam '
                             'output CSV. Default ","')
    parser.add_argument('--csv-header', action='store_true', default=False,
                        help='Tampilkan header CSV')
    parser.add_argument('--json', action='store_true', default=False,
                        help='Sembunyikan output verbose, hanya tampilkan '
                             'informasi dasar dalam format JSON. Kecepatan '
                             'dalam bit/s dan tidak terpengaruh oleh --bytes')
    parser.add_argument('--list', action='store_true',
                        help='Tampilkan daftar server speedtest.net '
                             'yang diurutkan berdasarkan jarak')
    parser.add_argument('--server', type=PARSER_TYPE_INT, action='append',
                        help='Tentukan ID server untuk diuji. Dapat '
                             'diberikan beberapa kali')
    parser.add_argument('--exclude', type=PARSER_TYPE_INT, action='append',
                        help='Kecualikan server dari pemilihan. Dapat '
                             'diberikan beberapa kali')
    parser.add_argument('--mini', help='URL server Speedtest Mini')
    parser.add_argument('--source', help='Alamat IP sumber untuk diikat')
    parser.add_argument('--timeout', default=10, type=PARSER_TYPE_FLOAT,
                        help='Timeout HTTP dalam detik. Default 10')
    parser.add_argument('--secure', action='store_true',
                        help='Gunakan HTTPS alih-alih HTTP saat berkomunikasi '
                             'dengan server yang dioperasikan speedtest.net')
    parser.add_argument('--no-pre-allocate', dest='pre_allocate',
                        action='store_const', default=True, const=False,
                        help='Jangan pra-alokasi data unggah. Pra-alokasi '
                             'diaktifkan secara default untuk meningkatkan '
                             'kinerja unggah. Untuk mendukung sistem dengan '
                             'memori tidak mencukupi, gunakan opsi ini untuk '
                             'menghindari MemoryError')
    parser.add_argument('--version', action='store_true',
                        help='Tampilkan nomor versi dan keluar')
    parser.add_argument('--debug', action='store_true',
                        help=ARG_SUPPRESS, default=ARG_SUPPRESS)

    options = parser.parse_args()
    if isinstance(options, tuple):
        args = options[0]
    else:
        args = options
    return args
def validate_optional_args(args):
    """Check if an argument was provided that depends on a module that may
    not be part of the Python standard library.

    If such an argument is supplied, and the module does not exist, exit
    with an error stating which module is missing.
    """
    optional_args = {
        'json': ('json/simplejson python module', json),
        'secure': ('SSL support', HTTPSConnection),
    }

    for arg, info in optional_args.items():
        if getattr(args, arg, False) and info[1] is None:
            raise SystemExit('%s tidak terinstal. --%s tidak '
                             'tersedia' % (info[0], arg))


def printer(string, quiet=False, debug=False, error=False, **kwargs):
    """Helper function print a string with various features"""

    if debug and not DEBUG:
        return

    if debug:
        if sys.stdout.isatty():
            out = '\033[1;30mDEBUG: %s\033[0m' % string
        else:
            out = 'DEBUG: %s' % string
    else:
        out = string

    if error:
        kwargs['file'] = sys.stderr

    if not quiet:
        print_(out, **kwargs)


def shell():
    """Run the full speedtest.net test"""

    global DEBUG
    shutdown_event = threading.Event()

    signal.signal(signal.SIGINT, ctrl_c(shutdown_event))

    args = parse_args()

    # Print the version and exit
    if args.version:
        version()

    if not args.download and not args.upload:
        raise SpeedtestCLIError('Tidak dapat memberikan --no-download dan '
                                '--no-upload')

    if len(args.csv_delimiter) != 1:
        raise SpeedtestCLIError('--csv-delimiter harus berupa satu karakter')

    if args.csv_header:
        csv_header(args.csv_delimiter)

    validate_optional_args(args)

    debug = getattr(args, 'debug', False)
    if debug == 'SUPPRESSHELP':
        debug = False
    if debug:
        DEBUG = True

    if args.simple or args.csv or args.json:
        quiet = True
    else:
        quiet = False

    if args.csv or args.json:
        machine_format = True
    else:
        machine_format = False

    # Don't set a callback if we are running quietly
    if quiet or debug:
        callback = do_nothing
    else:
        callback = print_dots(shutdown_event)

    printer('', quiet)
    try:
        speedtest = Speedtest(
            source_address=args.source,
            timeout=args.timeout,
            secure=args.secure
        )
    except (ConfigRetrievalError,) + HTTP_ERRORS:
        printer('Tidak dapat mengambil konfigurasi speedtest', error=True)
        raise SpeedtestCLIError(get_exception())

    if args.list:
        try:
            speedtest.get_servers()
        except (ServersRetrievalError,) + HTTP_ERRORS:
            printer('Tidak dapat mengambil daftar server speedtest', error=True)
            raise SpeedtestCLIError(get_exception())

        for _, servers in sorted(speedtest.servers.items()):
            for server in servers:
                line = ('%(id)5s) %(sponsor)s (%(name)s, %(country)s) '
                        '[%(d)0.2f km]' % server)
                try:
                    printer(line)
                except IOError:
                    e = get_exception()
                    if e.errno != errno.EPIPE:
                        raise
        sys.exit(0)
printer('*`✦ INFO - SPEEDTEST ✦`*\n', quiet)


    if not args.mini:
        printer('ᰔᩚ *Memulai tes...*', quiet)
        printer('ⴵ *Mencari server...*', quiet)
        try:
            speedtest.get_servers(servers=args.server, exclude=args.exclude)
        except NoMatchedServers:
            raise SpeedtestCLIError(
                '❒ *Tidak ada server yang cocok:* %s' %
                ', '.join('%s' % s for s in args.server)
            )
        except (ServersRetrievalError,) + HTTP_ERRORS:
            printer('❒ *Gagal mendapatkan daftar server.*', error=True)
            raise SpeedtestCLIError(get_exception())
        except InvalidServerIDType:
            raise SpeedtestCLIError(
                '%s adalah tipe server tidak valid, harus '
                'berupa integer' % ', '.join('%s' % s for s in args.server)
            )

        if args.server and len(args.server) == 1:
            printer('❍ *Mendapatkan info server...*', quiet)
        else:
            printer('❀ *Memilih server terbaik...*', quiet)
        speedtest.get_best_server()
    elif args.mini:
        speedtest.get_best_server(speedtest.set_mini_server(args.mini))

    results = speedtest.results

    printer('\n❖ *ISP:* %(isp)s' % speedtest.config['client'],
            quiet)
    printer('✎ *Server:* %(sponsor)s\n⚘ *Lokasi:* %(name)s [%(d)0.2f km] '
            '\n✰ *Latensi:* %(latency)s ms' % results.server, quiet)

    if args.download:
        printer('', quiet,
                end=('', '')[bool(debug)])
        speedtest.download(
            callback=callback,
            threads=(None, 1)[args.single]
        )
        printer('🜸 *Unduh:* %0.2f M%s/s' %
                ((results.download / 1000.0 / 1000.0) / args.units[1],
                 args.units[0]),
                quiet)
    else:
        printer('❒ *Melewati tes unduh.*', quiet)

    if args.upload:
        speedtest.upload()
        printer('✧ *Unggah:* %0.2f M%s/s' %
                ((results.upload / 1000.0 / 1000.0) / args.units[1],
                 args.units[0]),
                quiet)

    else:
        printer('❒ *Melewati tes unggah.*', quiet)

    printer('❒ *Hasil:*\n%r' % results.dict(), debug=True)

    if not args.simple and args.share:
        results.share()

    if args.simple:
        printer('✰ Latensi: %s ms\n🜸 Unduh: %0.2f M%s/s\n\n✧ Unggah: %0.2f M%s/s' %
                (results.ping,
                 (results.download / 1000.0 / 1000.0) / args.units[1],
                 args.units[0],
                 (results.upload / 1000.0 / 1000.0) / args.units[1],
                 args.units[0]))
    elif args.csv:
        printer(results.csv(delimiter=args.csv_delimiter))
    elif args.json:
        printer(results.json())

    if args.share and not machine_format:
        printer('\n❒ *Bagikan hasil:* %s' % results.share())


def main():
    try:
        shell()
    except KeyboardInterrupt:
        printer('\n❒ *Membatalkan...*', error=True)
    except (SpeedtestException, SystemExit):
        e = get_exception()
        # Ignore a successful exit, or argparse exit
        if getattr(e, 'code', 1) not in (0, 2):
            msg = '%s' % e
            if not msg:
                msg = '%r' % e
            raise SystemExit('ERROR: %s' % msg)


if __name__ == '__main__':
    main()