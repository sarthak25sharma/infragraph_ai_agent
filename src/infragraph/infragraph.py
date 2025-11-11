# InfraGraph 0.5.0
# License: MIT

import importlib
import logging
import json
import platform
import yaml
import requests
import urllib3
import io
import sys
import time
import grpc
import semantic_version
import types
import platform
import base64
import re
from google.protobuf import json_format

try:
    from infragraph import infragraph_pb2_grpc as pb2_grpc
except ImportError:
    import infragraph_pb2_grpc as pb2_grpc
try:
    from infragraph import infragraph_pb2 as pb2
except ImportError:
    import infragraph_pb2 as pb2

try:
    from typing import Union, Dict, List, Any, Literal
except ImportError:
    from typing_extensions import Literal


if sys.version_info[0] == 3:
    unicode = str


openapi_warnings = []

# instantiate the logger
stderr_handler = logging.StreamHandler(sys.stderr)
formatter = logging.Formatter(
    fmt="%(asctime)s.%(msecs)03d [%(name)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
formatter.converter = time.gmtime
stderr_handler.setFormatter(formatter)
log = logging.getLogger("infragraph")
log.addHandler(stderr_handler)


class Transport:
    HTTP = "http"
    GRPC = "grpc"


def api(
    location=None,
    transport=None,
    verify=True,
    logger=None,
    loglevel=logging.WARN,
    ext=None,
    version_check=False,
    otel_collector=None,
    otel_collector_transport="http",
):
    """Create an instance of an Api class

    generator.Generator outputs a base Api class with the following:
    - an abstract method for each OpenAPI path item object
    - a concrete properties for each unique OpenAPI path item parameter.

    generator.Generator also outputs an HttpApi class that inherits the base
    Api class, implements the abstract methods and uses the common HttpTransport
    class send_recv method to communicate with a REST based server.

    Args
    ----
    - location (str): The location of an Open Traffic Generator server.
    - transport (enum["http", "grpc"]): Transport Type
    - verify (bool): Verify the server's TLS certificate, or a string, in which
      case it must be a path to a CA bundle to use. Defaults to `True`.
      When set to `False`, requests will accept any TLS certificate presented by
      the server, and will ignore hostname mismatches and/or expired
      certificates, which will make your application vulnerable to
      man-in-the-middle (MitM) attacks. Setting verify to `False`
      may be useful during local development or testing.
    - logger (logging.Logger): A user defined logging.logger, if none is provided
      then a default logger with a stderr handler will be provided
    - loglevel (logging.loglevel): The logging package log level.
      The default loglevel is logging.INFO
    - ext (str): Name of an extension package
    """
    params = locals()

    if logger is not None:
        global log
        log = logger
    log.setLevel(loglevel)

    if version_check is False:
        log.warning("Version check is disabled")

    if otel_collector is not None:
        if sys.version_info[0] == 3 and sys.version_info[1] >= 7:
            log.info("Telemetry feature enabled")
        else:
            raise Exception(
                "Telemetry feature is only available for python version >= 3.7"
            )

    transport_types = ["http", "grpc"]
    if ext is None:
        transport = "http" if transport is None else transport
        if transport not in transport_types:
            raise Exception(
                "{transport} is not within valid transport types {transport_types}".format(
                    transport=transport, transport_types=transport_types
                )
            )
        if transport == "http":
            log.info("Transport set to HTTP")
            return HttpApi(**params)
        else:
            log.info("Transport set to GRPC")
            return GrpcApi(**params)
    try:
        if transport is not None:
            raise Exception(
                "ext and transport are not mutually exclusive. Please configure one of them."
            )
        lib = importlib.import_module("sanity_{}.infragraph_api".format(ext))
        return lib.Api(**params)
    except ImportError as err:
        msg = "Extension %s is not installed or invalid: %s"
        raise Exception(msg % (ext, err))


class HttpTransport(object):
    def __init__(self, **kwargs):
        """Use args from api() method to instantiate an HTTP transport"""
        self.location = (
            kwargs["location"]
            if "location" in kwargs and kwargs["location"] is not None
            else "https://localhost:443"
        )
        self.verify = kwargs["verify"] if "verify" in kwargs else False
        log.debug(
            "HttpTransport args: {}".format(
                ", ".join(["{}={!r}".format(k, v) for k, v in kwargs.items()])
            )
        )
        self.set_verify(self.verify)
        self._session = requests.Session()

    def set_verify(self, verify):
        self.verify = verify
        if self.verify is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            log.warning("Certificate verification is disabled")

    def _parse_response_error(self, response_code, response_text):
        error_response = ""
        try:
            error_response = yaml.safe_load(response_text)
        except Exception as _:
            error_response = response_text

        err_obj = Error()
        try:
            err_obj.deserialize(error_response)
        except Exception as _:
            err_obj.code = response_code
            err_obj.errors = [str(error_response)]

        raise Exception(err_obj)

    def send_recv(
        self,
        method,
        relative_url,
        payload=None,
        return_object=None,
        headers=None,
        request_class=None,
    ):
        url = "%s%s" % (self.location, relative_url)
        data = None
        headers = headers or {"Content-Type": "application/json"}
        if payload is not None:
            if isinstance(payload, bytes):
                data = payload
                headers["Content-Type"] = "application/octet-stream"
            elif isinstance(payload, (str, unicode)):
                if request_class is not None:
                    request_class().deserialize(payload)
                data = payload
            elif isinstance(payload, OpenApiBase):
                data = payload.serialize()
            else:
                raise Exception("Type of payload provided is unknown")
        log.debug("Request url - " + str(url))
        log.debug("Method - " + str(method))
        log.debug("Request headers - " + str(headers))
        log.debug("Request payload - " + str(data))
        response = self._session.request(
            method=method,
            url=url,
            data=data,
            verify=False,
            allow_redirects=True,
            # TODO: add a timeout here
            headers=headers,
        )
        log.debug("Response status code - " + str(response.status_code))
        log.debug("Response header - " + str(response.headers))
        log.debug("Response content - " + str(response.content))
        log.debug("Response text - " + str(response.text))
        if response.ok:
            if "application/json" in response.headers["content-type"]:
                # TODO: we might want to check for utf-8 charset and decode
                # accordingly, but current impl works for now
                response_dict = yaml.safe_load(response.text)
                if return_object is None:
                    # if response type is not provided, return dictionary
                    # instead of python object
                    return response_dict
                else:
                    return return_object.deserialize(response_dict)
            elif "application/octet-stream" in response.headers["content-type"]:
                return io.BytesIO(response.content)
            else:
                # TODO: for now, return bare response object for unknown
                # content types
                return response
        else:
            self._parse_response_error(response.status_code, response.text)


class OpenApiStatus:
    messages = {}
    # logger = logging.getLogger(__module__)

    @classmethod
    def warn(cls, key, object):
        if cls.messages.get(key) is not None:
            if cls.messages[key] in object.__warnings__:
                return
            # cls.logger.warning(cls.messages[key])
            logging.warning(cls.messages[key])
            object.__warnings__.append(cls.messages[key])
            log.warning(
                "["
                + OpenApiStatus.warn.__name__
                + "] cls.messages[key]-"
                + cls.messages[key]
            )
            # openapi_warnings.append(cls.messages[key])

    @staticmethod
    def deprecated(func_or_data):
        def inner(self, *args, **kwargs):
            OpenApiStatus.warn(
                "{}.{}".format(type(self).__name__, func_or_data.__name__),
                self,
            )
            return func_or_data(self, *args, **kwargs)

        if isinstance(func_or_data, types.FunctionType):
            return inner
        OpenApiStatus.warn(func_or_data)
        log.warning(
            "[" + OpenApiStatus.deprecated.__name__ + "] func_or_data-" + func_or_data
        )

    @staticmethod
    def under_review(func_or_data):
        def inner(self, *args, **kwargs):
            OpenApiStatus.warn(
                "{}.{}".format(type(self).__name__, func_or_data.__name__),
                self,
            )
            return func_or_data(self, *args, **kwargs)

        if isinstance(func_or_data, types.FunctionType):
            return inner
        OpenApiStatus.warn(func_or_data)
        log.warning(
            "[" + OpenApiStatus.under_review.__name__ + "] func_or_data-" + func_or_data
        )


class OpenApiBase(object):
    """Base class for all generated classes"""

    JSON = "json"
    YAML = "yaml"
    DICT = "dict"

    __slots__ = ()

    __constraints__ = {"global": []}
    __validate_latter__ = {"unique": [], "constraint": []}

    def __init__(self):
        pass

    def serialize(self, encoding=JSON):
        """Serialize the current object according to a specified encoding.

        Args
        ----
        - encoding (str[json, yaml, dict]): The object will be recursively
            serialized according to the specified encoding.
            The supported encodings are json, yaml and python dict.

        Returns
        -------
        - obj(Union[str, dict]): A str or dict object depending on the specified
            encoding. The json and yaml encodings will return a str object and
            the dict encoding will return a python dict object.
        """
        # TODO: restore behavior
        # self._clear_globals()
        if encoding == OpenApiBase.JSON:
            data = json.dumps(self._encode(), indent=2, sort_keys=True)
        elif encoding == OpenApiBase.YAML:
            data = yaml.safe_dump(self._encode())
        elif encoding == OpenApiBase.DICT:
            data = self._encode()
        else:
            raise NotImplementedError("Encoding %s not supported" % encoding)
        # TODO: restore behavior
        # self._validate_coded()
        return data

    def _encode(self):
        raise NotImplementedError()

    def deserialize(self, serialized_object):
        """Deserialize a python object into the current object.

        If the input `serialized_object` does not match the current
        openapi object an exception will be raised.

        Args
        ----
        - serialized_object (Union[str, dict]): The object to deserialize.
            If the serialized_object is of type str then the internal encoding
            of the serialized_object must be json or yaml.

        Returns
        -------
        - obj(OpenApiObject): This object with all the
            serialized_object deserialized within.
        """
        # TODO: restore behavior
        # self._clear_globals()
        if isinstance(serialized_object, (str, unicode)):
            serialized_object = yaml.safe_load(serialized_object)
        self._decode(serialized_object)
        # TODO: restore behavior
        # self._validate_coded()
        return self

    def _decode(self, dict_object):
        raise NotImplementedError()

    def warnings(self):
        warns = list(self.__warnings__)
        if "2.7" in platform.python_version().rsplit(".", 1)[0]:
            del self.__warnings__[:]
        else:
            self.__warnings__.clear()
        return warns


class OpenApiValidator(object):

    __slots__ = ()

    _validation_errors = []

    def __init__(self):
        pass

    def _clear_errors(self):
        if "2.7" in platform.python_version().rsplit(".", 1)[0]:
            del self._validation_errors[:]
        else:
            self._validation_errors.clear()

    def validate_mac(self, mac):
        if mac is None or not isinstance(mac, (str, unicode)) or mac.count(" ") != 0:
            return False
        try:
            if len(mac) != 17:
                return False
            return all([0 <= int(oct, 16) <= 255 for oct in mac.split(":")])
        except Exception:
            log.debug("Validating MAC address - " + str(mac) + " failed ")
            return False

    def validate_ipv4(self, ip):
        if ip is None or not isinstance(ip, (str, unicode)) or ip.count(" ") != 0:
            return False
        if len(ip.split(".")) != 4:
            return False
        try:
            return all([0 <= int(oct) <= 255 for oct in ip.split(".", 3)])
        except Exception:
            log.debug("Validating IPv4 address - " + str(ip) + " failed")
            return False

    def validate_ipv6(self, ip):
        if ip is None or not isinstance(ip, (str, unicode)):
            return False
        ip = ip.strip()
        if (
            ip.count(" ") > 0
            or ip.count(":") > 7
            or ip.count("::") > 1
            or ip.count(":::") > 0
        ):
            return False
        if (ip[0] == ":" and ip[:2] != "::") or (ip[-1] == ":" and ip[-2:] != "::"):
            return False
        if ip.count("::") == 0 and ip.count(":") != 7:
            return False
        if ip == "::":
            return True
        if ip[:2] == "::":
            ip = ip.replace("::", "0:")
        elif ip[-2:] == "::":
            ip = ip.replace("::", ":0")
        else:
            ip = ip.replace("::", ":0:")
        try:
            return all(
                [
                    True
                    if (0 <= int(oct, 16) <= 65535) and (1 <= len(oct) <= 4)
                    else False
                    for oct in ip.split(":")
                ]
            )
        except Exception:
            log.debug("Validating IPv6 address - " + str(ip) + " failed")
            return False

    def validate_hex(self, hex):
        if hex is None or not isinstance(hex, (str, unicode)):
            return False
        try:
            int(hex, 16)
            return True
        except Exception:
            log.debug("Validating HEX value - " + str(hex) + " failed")
            return False

    def validate_integer(self, value, min, max, type_format=None):
        if value is None or not isinstance(value, int):
            return False
        if min is not None and value < min:
            return False
        if max is not None and value > max:
            return False
        if type_format is not None:
            if type_format == "uint32" and (value < 0 or value > 4294967295):
                return False
            elif type_format == "uint64" and (
                value < 0 or value > 18446744073709551615
            ):
                return False
            elif type_format == "int32" and (value < -2147483648 or value > 2147483647):
                return False
            elif type_format == "int64" and (
                value < -9223372036854775808 or value > 9223372036854775807
            ):
                return False
        return True

    def validate_float(self, value):
        return isinstance(value, (int, float))

    def validate_string(self, value, min_length, max_length, pattern):
        if value is None or not isinstance(value, (str, unicode)):
            return False
        if min_length is not None and len(value) < min_length:
            return False
        if max_length is not None and len(value) > max_length:
            return False
        if pattern is not None and not re.match(pattern, value):
            return False
        return True

    def validate_bool(self, value):
        return isinstance(value, bool)

    def validate_list(self, value, itemtype, min, max, min_length, max_length, pattern):
        if value is None or not isinstance(value, list):
            return False
        v_obj = getattr(self, "validate_{}".format(itemtype), None)
        if v_obj is None:
            raise AttributeError("{} is not a valid attribute".format(itemtype))
        v_obj_lst = []
        for item in value:
            if itemtype == "integer":
                v_obj_lst.append(v_obj(item, min, max))
            elif itemtype == "string":
                v_obj_lst.append(v_obj(item, min_length, max_length, pattern))
            else:
                v_obj_lst.append(v_obj(item))
        return v_obj_lst

    def validate_binary(self, value):
        if isinstance(value, bytes):
            return True

        if not isinstance(value, str):
            return False

        try:
            base64.b64decode(value, validate=True)
            return True
        except Exception:
            pass

        # Fallback: validate as a string of '0's and '1's
        if not value:  # An empty string is not a valid binary string in this context
            return False

        return all(char in "01" for char in value)

    def validate_oid(self, value):
        segments = value.split(".")
        if len(segments) < 2:
            return False
        for segment in segments:
            if not segment.isnumeric():
                return False
            if not (0 <= int(segment) <= 4294967295):
                return False
        return True

    def types_validation(
        self,
        value,
        type_,
        err_msg,
        itemtype=None,
        min=None,
        max=None,
        min_length=None,
        max_length=None,
        pattern=None,
    ):
        type_map = {
            int: "integer",
            str: "string",
            float: "float",
            bool: "bool",
            list: "list",
            "int64": "integer",
            "int32": "integer",
            "uint64": "integer",
            "uint32": "integer",
            "double": "float",
        }
        type_format = type_
        if type_ in type_map:
            type_ = type_map[type_]
        if itemtype is not None and itemtype in type_map:
            itemtype = type_map[itemtype]
        v_obj = getattr(self, "validate_{}".format(type_), None)
        if v_obj is None:
            msg = "{} is not a valid or unsupported format".format(type_)
            raise TypeError(msg)
        if type_ == "list":
            verdict = v_obj(value, itemtype, min, max, min_length, max_length, pattern)
            if all(verdict) is True:
                return
            err_msg = "{} \n {} are not valid".format(
                err_msg,
                [value[index] for index, item in enumerate(verdict) if item is False],
            )
            verdict = False
        elif type_ == "integer":
            verdict = v_obj(value, min, max, type_format)
            if verdict is True:
                return
            min_max = ""
            if min is not None:
                min_max = ", expected min {}".format(min)
            if max is not None:
                min_max = min_max + ", expected max {}".format(max)
            err_msg = "{} \n got {} of type {} {}".format(
                err_msg, value, type(value), min_max
            )
        elif type_ == "string":
            verdict = v_obj(value, min_length, max_length, pattern)
            if verdict is True:
                return
            msg = ""
            if min_length is not None:
                msg = ", expected min {}".format(min_length)
            if max_length is not None:
                msg = msg + ", expected max {}".format(max_length)
            if pattern is not None:
                msg = msg + ", expected pattern '{}'".format(pattern)
            err_msg = "{} \n got {} of type {} {}".format(
                err_msg, value, type(value), msg
            )
        else:
            verdict = v_obj(value)
        if verdict is False:
            raise TypeError(err_msg)

    def _validate_unique_and_name(self, name, value, latter=False):
        if self._TYPES[name].get("unique") is None or value is None:
            return
        if latter is True:
            self.__validate_latter__["unique"].append(
                (self._validate_unique_and_name, name, value)
            )
            return
        class_name = type(self).__name__
        unique_type = self._TYPES[name]["unique"]
        if class_name not in self.__constraints__:
            self.__constraints__[class_name] = dict()
        if unique_type == "global":
            values = self.__constraints__["global"]
        else:
            values = self.__constraints__[class_name]
        if value in values:
            self._validation_errors.append(
                "{} with {} already exists".format(name, value)
            )
            return
        if isinstance(values, list):
            values.append(value)
        self.__constraints__[class_name].update({value: self})

    def _validate_constraint(self, name, value, latter=False):
        cons = self._TYPES[name].get("constraint")
        if cons is None or value is None:
            return
        if latter is True:
            self.__validate_latter__["constraint"].append(
                (self._validate_constraint, name, value)
            )
            return
        found = False
        for c in cons:
            klass, prop = c.split(".")
            names = self.__constraints__.get(klass, {})
            props = [obj._properties.get(prop) for obj in names.values()]
            if value in props:
                found = True
                break
        if found is not True:
            self._validation_errors.append(
                "{} is not a valid type of {}".format(value, "||".join(cons))
            )
            return

    def _validate_coded(self):
        for item in self.__validate_latter__["unique"]:
            item[0](item[1], item[2])
        for item in self.__validate_latter__["constraint"]:
            item[0](item[1], item[2])
        self._clear_vars()
        if len(self._validation_errors) > 0:
            errors = "\n".join(self._validation_errors)
            self._clear_errors()
            raise Exception(errors)

    def _clear_vars(self):
        if platform.python_version_tuple()[0] == "2":
            self.__validate_latter__["unique"] = []
            self.__validate_latter__["constraint"] = []
        else:
            self.__validate_latter__["unique"].clear()
            self.__validate_latter__["constraint"].clear()

    def _clear_globals(self):
        keys = list(self.__constraints__.keys())
        for k in keys:
            if k == "global":
                self.__constraints__["global"] = []
                continue
            del self.__constraints__[k]


class OpenApiObject(OpenApiBase, OpenApiValidator):
    """Base class for any /components/schemas object

    Every OpenApiObject is reuseable within the schema so it can
    exist in multiple locations within the hierarchy.
    That means it can exist in multiple locations as a
    leaf, parent/choice or parent.
    """

    __slots__ = ("__warnings__", "_properties", "_parent", "_choice")
    _DEFAULTS = {}
    _TYPES = {}
    _REQUIRED = []
    _STATUS = {}

    def __init__(self, parent=None, choice=None):
        super(OpenApiObject, self).__init__()
        self._parent = parent
        self._choice = choice
        self._properties = {}
        self.__warnings__ = []

    @property
    def parent(self):
        return self._parent

    def _set_choice(self, name):
        if self._has_choice(name):
            for enum in self._TYPES["choice"]["enum"]:
                if enum in self._properties and name != enum:
                    self._properties.pop(enum)
            self._properties["choice"] = name

    def _has_choice(self, name):
        if (
            "choice" in dir(self)
            and "_TYPES" in dir(self)
            and "choice" in self._TYPES
            and name in self._TYPES["choice"]["enum"]
        ):
            return True
        else:
            return False

    def _get_property(self, name, default_value=None, parent=None, choice=None):
        if name in self._properties and self._properties[name] is not None:
            return self._properties[name]
        if isinstance(default_value, type) is True:
            self._set_choice(name)
            if "_choice" in default_value.__slots__:
                self._properties[name] = default_value(parent=parent, choice=choice)
            else:
                self._properties[name] = default_value(parent=parent)
            if (
                "_DEFAULTS" in dir(self._properties[name])
                and "choice" in self._properties[name]._DEFAULTS
            ):
                choice_str = self._properties[name]._DEFAULTS["choice"]

                if choice_str in self._properties[name]._TYPES:
                    getattr(
                        self._properties[name],
                        self._properties[name]._DEFAULTS["choice"],
                    )
        else:
            if default_value is None and name in self._DEFAULTS:
                self._set_choice(name)
                self._properties[name] = self._DEFAULTS[name]
            else:
                self._properties[name] = default_value
        return self._properties[name]

    def _set_property(self, name, value, choice=None):
        if name == "choice":

            if (
                self.parent is None
                and value is not None
                and value not in self._TYPES["choice"]["enum"]
            ):
                raise Exception(
                    "%s is not a valid choice, valid choices are %s"
                    % (value, ", ".join(self._TYPES["choice"]["enum"]))
                )

            self._set_choice(value)
            if name in self._DEFAULTS and value is None:
                self._properties[name] = self._DEFAULTS[name]
        elif name in self._DEFAULTS and value is None:
            self._set_choice(name)
            self._properties[name] = self._DEFAULTS[name]
        else:
            self._set_choice(name)
            self._properties[name] = value
        # TODO: restore behavior
        # self._validate_unique_and_name(name, value)
        # self._validate_constraint(name, value)
        if self._parent is not None and self._choice is not None and value is not None:
            self._parent._set_property("choice", self._choice)

    def _encode(self):
        """Helper method for serialization"""
        output = {}
        self._raise_status_warnings(self, None)
        self._validate_required()
        for key, value in self._properties.items():
            self._validate_types(key, value)
            # TODO: restore behavior
            # self._validate_unique_and_name(key, value, True)
            # self._validate_constraint(key, value, True)
            if isinstance(value, (OpenApiObject, OpenApiIter)):
                output[key] = value._encode()
                if isinstance(value, OpenApiObject):
                    self._raise_status_warnings(key, value)
            elif value is not None:
                if (
                    self._TYPES.get(key, {}).get("format", "") == "int64"
                    or self._TYPES.get(key, {}).get("format", "") == "uint64"
                ):
                    value = str(value)
                elif (
                    self._TYPES.get(key, {}).get("itemformat", "") == "int64"
                    or self._TYPES.get(key, {}).get("itemformat", "") == "uint64"
                ):
                    value = [str(v) for v in value]
                output[key] = value
                self._raise_status_warnings(key, value)
        return output

    def _decode(self, obj):
        dtypes = [list, str, int, float, bool]
        self._raise_status_warnings(self, None)
        for property_name, property_value in obj.items():
            if property_name in self._TYPES:
                ignore_warnings = False
                if isinstance(property_value, dict):
                    child = self._get_child_class(property_name)
                    if "choice" in child[1]._TYPES and "_parent" in child[1].__slots__:
                        property_value = child[1](self, property_name)._decode(
                            property_value
                        )
                    elif "_parent" in child[1].__slots__:
                        property_value = child[1](self)._decode(property_value)
                    else:
                        property_value = child[1]()._decode(property_value)
                elif (
                    isinstance(property_value, list)
                    and property_name in self._TYPES
                    and self._TYPES[property_name]["type"] not in dtypes
                ):
                    child = self._get_child_class(property_name, True)
                    openapi_list = child[0]()
                    for item in property_value:
                        item = child[1]()._decode(item)
                        openapi_list._items.append(item)
                    property_value = openapi_list
                    ignore_warnings = True
                elif property_name in self._DEFAULTS and property_value is None:
                    if isinstance(self._DEFAULTS[property_name], tuple(dtypes)):
                        property_value = self._DEFAULTS[property_name]
                self._set_choice(property_name)
                # convert int64(will be string on wire) to to int
                if (
                    self._TYPES[property_name].get("format", "") == "int64"
                    or self._TYPES[property_name].get("format", "") == "uint64"
                ):
                    property_value = int(property_value)
                elif (
                    self._TYPES[property_name].get("itemformat", "") == "int64"
                    or self._TYPES[property_name].get("itemformat", "") == "uint64"
                ):
                    property_value = [int(v) for v in property_value]
                self._properties[property_name] = property_value
                # TODO: restore behavior
                # OpenApiStatus.warn(
                #     "{}.{}".format(type(self).__name__, property_name), self
                # )
                if not ignore_warnings:
                    self._raise_status_warnings(property_name, property_value)
            self._validate_types(property_name, property_value)
            # TODO: restore behavior
            # self._validate_unique_and_name(property_name, property_value, True)
            # self._validate_constraint(property_name, property_value, True)
        self._validate_required()
        return self

    def _get_child_class(self, property_name, is_property_list=False):
        list_class = None
        class_name = self._TYPES[property_name]["type"]
        module = globals().get(self.__module__)
        if module is None:
            module = importlib.import_module(self.__module__)
            globals()[self.__module__] = module
        object_class = getattr(module, class_name)
        if is_property_list is True:
            list_class = object_class
            object_class = getattr(module, class_name[0:-4])
        return (list_class, object_class)

    def __str__(self):
        return self.serialize(encoding=self.YAML)

    def __deepcopy__(self, memo):
        """Creates a deep copy of the current object"""
        return self.__class__().deserialize(self.serialize())

    def __copy__(self):
        """Creates a deep copy of the current object"""
        return self.__deepcopy__(None)

    def __eq__(self, other):
        return self.__str__() == other.__str__()

    def clone(self):
        """Creates a deep copy of the current object"""
        return self.__deepcopy__(None)

    def _validate_required(self):
        """Validates the required properties are set
        Use getattr as it will set any defaults prior to validating
        """
        if getattr(self, "_REQUIRED", None) is None:
            return
        for name in self._REQUIRED:
            if self._properties.get(name) is None:
                msg = (
                    "{} is a mandatory property of {}"
                    " and should not be set to None".format(
                        name,
                        self.__class__,
                    )
                )
                raise ValueError(msg)

    def _validate_types(self, property_name, property_value):
        common_data_types = [list, str, int, float, bool]
        if property_name not in self._TYPES:
            # raise ValueError("Invalid Property {}".format(property_name))
            return
        details = self._TYPES[property_name]
        if (
            property_value is None
            and property_name not in self._DEFAULTS
            and property_name not in self._REQUIRED
        ):
            return
        if "enum" in details and property_value not in details["enum"]:
            raise_error = False
            if isinstance(property_value, list):
                for value in property_value:
                    if value not in details["enum"]:
                        raise_error = True
                        break
            elif property_value not in details["enum"]:
                raise_error = True

            if raise_error is True:
                msg = "property {} shall be one of these" " {} enum, but got {} at {}"
                raise TypeError(
                    msg.format(
                        property_name,
                        details["enum"],
                        property_value,
                        self.__class__,
                    )
                )
        if details["type"] in common_data_types and "format" not in details:
            msg = "property {} shall be of type {} at {}".format(
                property_name, details["type"], self.__class__
            )

            itemtype = (
                details.get("itemformat")
                if "itemformat" in details
                else details.get("itemtype")
            )
            self.types_validation(
                property_value,
                details["type"],
                msg,
                itemtype,
                details.get("minimum"),
                details.get("maximum"),
                details.get("minLength"),
                details.get("maxLength"),
                details.get("pattern"),
            )

        if details["type"] not in common_data_types:
            class_name = details["type"]
            # TODO Need to revisit importlib
            module = importlib.import_module(self.__module__)
            object_class = getattr(module, class_name)
            if not isinstance(property_value, object_class):
                msg = "property {} shall be of type {}," " but got {} at {}"
                raise TypeError(
                    msg.format(
                        property_name,
                        class_name,
                        type(property_value),
                        self.__class__,
                    )
                )
        if "format" in details:
            msg = "Invalid {} format, expected {} at {}".format(
                property_value, details["format"], self.__class__
            )
            _type = details["type"] if details["type"] is list else details["format"]
            self.types_validation(
                property_value,
                _type,
                msg,
                details["format"],
                details.get("minimum"),
                details.get("maximum"),
                details.get("minLength"),
                details.get("maxLength"),
                details.get("pattern"),
            )

    def validate(self):
        self._validate_required()
        for key, value in self._properties.items():
            self._validate_types(key, value)
        # TODO: restore behavior
        # self._validate_coded()

    def get(self, name, with_default=False):
        """
        getattr for openapi object
        """
        if self._properties.get(name) is not None:
            return self._properties[name]
        elif with_default:
            # TODO need to find a way to avoid getattr
            choice = self._properties.get("choice") if "choice" in dir(self) else None
            getattr(self, name)
            if "choice" in dir(self):
                if choice is None and "choice" in self._properties:
                    self._properties.pop("choice")
                else:
                    self._properties["choice"] = choice
            return self._properties.pop(name)
        return None

    def _raise_status_warnings(self, property_name, property_value):
        if len(self._STATUS) > 0:

            if isinstance(property_name, OpenApiObject):
                if "self" in self._STATUS and property_value is None:
                    print("[WARNING]: %s" % self._STATUS["self"], file=sys.stderr)

                return

            enum_key = "%s.%s" % (property_name, property_value)
            if property_name in self._STATUS:
                print(
                    "[WARNING]: %s" % self._STATUS[property_name],
                    file=sys.stderr,
                )
            elif enum_key in self._STATUS:
                print("[WARNING]: %s" % self._STATUS[enum_key], file=sys.stderr)


class OpenApiIter(OpenApiBase):
    """Container class for OpenApiObject

    Inheriting classes contain 0..n instances of an OpenAPI components/schemas
    object.
    - config.flows.flow(name="1").flow(name="2").flow(name="3")

    The __getitem__ method allows getting an instance using ordinal.
    - config.flows[0]
    - config.flows[1:]
    - config.flows[0:1]
    - f1, f2, f3 = config.flows

    The __iter__ method allows for iterating across the encapsulated contents
    - for flow in config.flows:
    """

    __slots__ = ("_index", "_items")
    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self):
        super(OpenApiIter, self).__init__()
        self._index = -1
        self._items = []

    def __len__(self):
        return len(self._items)

    def _getitem(self, key):
        found = None
        if isinstance(key, int):
            found = self._items[key]
        elif isinstance(key, slice) is True:
            start, stop, step = key.indices(len(self))
            sliced = self.__class__()
            for i in range(start, stop, step):
                sliced._items.append(self._items[i])
            return sliced
        elif isinstance(key, str):
            for item in self._items:
                if item.name == key:
                    found = item
        if found is None:
            raise IndexError()
        if (
            self._GETITEM_RETURNS_CHOICE_OBJECT is True
            and found._properties.get("choice") is not None
            and found._properties.get(found._properties["choice"]) is not None
        ):
            return found._properties[found._properties["choice"]]
        return found

    def _iter(self):
        self._index = -1
        return self

    def _next(self):
        if self._index + 1 >= len(self._items):
            raise StopIteration
        else:
            self._index += 1
        return self.__getitem__(self._index)

    def __getitem__(self, key):
        raise NotImplementedError("This should be overridden by the generator")

    def _add(self, item):
        self._items.append(item)
        self._index = len(self._items) - 1

    def remove(self, index):
        del self._items[index]
        self._index = len(self._items) - 1

    def append(self, item):
        """Append an item to the end of OpenApiIter
        TBD: type check, raise error on mismatch
        """
        self._instanceOf(item)
        self._add(item)
        return self

    def clear(self):
        del self._items[:]
        self._index = -1

    def set(self, index, item):
        self._instanceOf(item)
        self._items[index] = item
        return self

    def _encode(self):
        return [item._encode() for item in self._items]

    def _decode(self, encoded_list):
        item_class_name = self.__class__.__name__.replace("Iter", "")
        module = importlib.import_module(self.__module__)
        object_class = getattr(module, item_class_name)
        self.clear()
        for item in encoded_list:
            self._add(object_class()._decode(item))

    def __copy__(self):
        raise NotImplementedError(
            "Shallow copy of OpenApiIter objects is not supported"
        )

    def __deepcopy__(self, memo):
        raise NotImplementedError("Deep copy of OpenApiIter objects is not supported")

    def __str__(self):
        return yaml.safe_dump(self._encode())

    def __eq__(self, other):
        return self.__str__() == other.__str__()

    def _instanceOf(self, item):
        raise NotImplementedError("validating an OpenApiIter object is not supported")


class Telemetry(object):
    def __init__(self, endpoint, transport):
        self.transport = transport
        self.endpoint = endpoint
        self.is_telemetry_enabled = False
        self._tracer = None
        self._trace_provider = None
        self._resource = None
        self._batch_span_processor = None
        self._trace = None
        self._http_exporter = None
        self._grpc_exporter = None
        self._http_instrumentor = None
        self._grpc_instrumentor = None
        self._spankind = None
        if self.endpoint is not None:
            self.is_telemetry_enabled = True
            self._initiate_tracer()

    def _initiate_tracer(self):
        import warnings

        warnings.filterwarnings("ignore", category=DeprecationWarning)
        self._trace = importlib.import_module("opentelemetry.trace")
        self._spankind = getattr(self._trace, "SpanKind")
        self._trace_provider = importlib.import_module("opentelemetry.sdk.trace")
        self._trace_provider = getattr(self._trace_provider, "TracerProvider")
        self._resource = importlib.import_module("opentelemetry.sdk.resources")
        self._resource = getattr(self._resource, "Resource")
        self._batch_span_processor = importlib.import_module(
            "opentelemetry.sdk.trace.export"
        )
        self._batch_span_processor = getattr(
            self._batch_span_processor, "BatchSpanProcessor"
        )
        self._grpc_exporter = importlib.import_module(
            "opentelemetry.exporter.otlp.proto.grpc.trace_exporter"
        )
        self._grpc_exporter = getattr(self._grpc_exporter, "OTLPSpanExporter")
        self._http_exporter = importlib.import_module(
            "opentelemetry.exporter.otlp.proto.http.trace_exporter"
        )
        self._http_exporter = getattr(self._http_exporter, "OTLPSpanExporter")

        provider = self._trace_provider(
            resource=self._resource.create({"service.name": "snappi"})
        )
        self._trace.set_tracer_provider(provider)
        if self.transport == "http":
            otlp_exporter = self._http_exporter(endpoint=self.endpoint)
        else:
            otlp_exporter = self._grpc_exporter(endpoint=self.endpoint, insecure=True)
        span_processor = self._batch_span_processor(otlp_exporter)
        provider.add_span_processor(span_processor)
        tracer = self._trace.get_tracer(__name__)
        self._tracer = tracer

    def initiate_http_instrumentation(self):
        if self.is_telemetry_enabled:
            from opentelemetry.instrumentation.requests import (
                RequestsInstrumentor,
            )

            RequestsInstrumentor().instrument()

    def initiate_grpc_instrumentation(self):
        if self.is_telemetry_enabled:
            from opentelemetry.instrumentation.grpc import (
                GrpcInstrumentorClient,
            )

            GrpcInstrumentorClient().instrument()

    def set_span_event(self, message):
        if self.is_telemetry_enabled:
            current_span = self._trace.get_current_span()
            current_span.add_event(message)

    @staticmethod
    def create_child_span(func):
        def tracing(self, *args, **kwargs):
            telemetry = self._telemetry
            if telemetry.is_telemetry_enabled:
                name = func.__name__
                with self.tracer().start_as_current_span(
                    name, kind=telemetry._spankind.CLIENT
                ):
                    return func(self, *args, **kwargs)
            else:
                return func(self, *args, **kwargs)

        return tracing


class Infrastructure(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "name": {
            "type": str,
            "pattern": r"^[\sa-zA-Z0-9-_()><\[\]]+$",
        },
        "description": {"type": str},
        "devices": {"type": "DeviceIter"},
        "links": {"type": "LinkIter"},
        "instances": {"type": "InstanceIter"},
        "edges": {"type": "InfrastructureEdgeIter"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, name=None, description=None):
        super(Infrastructure, self).__init__()
        self._parent = parent
        self._set_property("name", name)
        self._set_property("description", description)

    def set(self, name=None, description=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def name(self):
        # type: () -> str
        """name getter

        The name of the infrastructure.. Globally unique name of an object. It also serves as the primary key for arrays of objects.

        Returns: str
        """
        return self._get_property("name")

    @name.setter
    def name(self, value):
        """name setter

        The name of the infrastructure.. Globally unique name of an object. It also serves as the primary key for arrays of objects.

        value: str
        """
        self._set_property("name", value)

    @property
    def description(self):
        # type: () -> str
        """description getter

        A detailed description of the infrastructure.

        Returns: str
        """
        return self._get_property("description")

    @description.setter
    def description(self, value):
        """description setter

        A detailed description of the infrastructure.

        value: str
        """
        self._set_property("description", value)

    @property
    def devices(self):
        # type: () -> DeviceIter
        """devices getter

        An inventory of devices and components.

        Returns: DeviceIter
        """
        return self._get_property("devices", DeviceIter, self._parent, self._choice)

    @property
    def links(self):
        # type: () -> LinkIter
        """links getter

        An inventory of the links present in the infrastructure edges.

        Returns: LinkIter
        """
        return self._get_property("links", LinkIter, self._parent, self._choice)

    @property
    def instances(self):
        # type: () -> InstanceIter
        """instances getter

        An inventory of the device instances present in the infrastructure edges.

        Returns: InstanceIter
        """
        return self._get_property("instances", InstanceIter, self._parent, self._choice)

    @property
    def edges(self):
        # type: () -> InfrastructureEdgeIter
        """edges getter

        An array of edge objects used to connect instance devices and components to other instance. devices and components. These edge objects are used to form fully qualified qualified graph.

        Returns: InfrastructureEdgeIter
        """
        return self._get_property(
            "edges", InfrastructureEdgeIter, self._parent, self._choice
        )


class Device(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "name": {
            "type": str,
            "pattern": r"^[\sa-zA-Z0-9-_()><\[\]]+$",
        },
        "description": {"type": str},
        "components": {"type": "ComponentIter"},
        "links": {"type": "LinkIter"},
        "edges": {"type": "DeviceEdgeIter"},
    }  # type: Dict[str, str]

    _REQUIRED = ("name", "components", "links", "edges")  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, name=None, description=None):
        super(Device, self).__init__()
        self._parent = parent
        self._set_property("name", name)
        self._set_property("description", description)

    def set(self, name=None, description=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def name(self):
        # type: () -> str
        """name getter

        The name of the device being described.. Globally unique name of an object. It also serves as the primary key for arrays of objects.

        Returns: str
        """
        return self._get_property("name")

    @name.setter
    def name(self, value):
        """name setter

        The name of the device being described.. Globally unique name of an object. It also serves as the primary key for arrays of objects.

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property name as None")
        self._set_property("name", value)

    @property
    def description(self):
        # type: () -> str
        """description getter

        A description of the device.. This will not be used in Infrastructure.connections.

        Returns: str
        """
        return self._get_property("description")

    @description.setter
    def description(self, value):
        """description setter

        A description of the device.. This will not be used in Infrastructure.connections.

        value: str
        """
        self._set_property("description", value)

    @property
    def components(self):
        # type: () -> ComponentIter
        """components getter

        TBD

        Returns: ComponentIter
        """
        return self._get_property(
            "components", ComponentIter, self._parent, self._choice
        )

    @property
    def links(self):
        # type: () -> LinkIter
        """links getter

        All the links that make up this device.

        Returns: LinkIter
        """
        return self._get_property("links", LinkIter, self._parent, self._choice)

    @property
    def edges(self):
        # type: () -> DeviceEdgeIter
        """edges getter

        An array of edges that are used to produce device graph.. These are used to connect components to each other or components. to other device components (composability).. The generated graph edges will be fully qualified using the count property. of the device and component and slice notation of each endpoint in the edge object.

        Returns: DeviceEdgeIter
        """
        return self._get_property("edges", DeviceEdgeIter, self._parent, self._choice)


class Component(OpenApiObject):
    __slots__ = ("_parent", "_choice")

    _TYPES = {
        "name": {
            "type": str,
            "pattern": r"^[\sa-zA-Z0-9-_()><\[\]]+$",
        },
        "description": {"type": str},
        "count": {
            "type": int,
            "format": "int32",
        },
        "choice": {
            "type": str,
            "enum": [
                "custom",
                "device",
                "cpu",
                "npu",
                "nic",
                "memory",
                "port",
                "switch",
            ],
        },
        "custom": {"type": "ComponentCustom"},
        "device": {"type": "ComponentDevice"},
        "cpu": {"type": "ComponentCpu"},
        "npu": {"type": "ComponentNpu"},
        "nic": {"type": "ComponentNic"},
        "memory": {"type": "ComponentMemory"},
        "port": {"type": "ComponentPort"},
        "switch": {"type": "ComponentSwitch"},
    }  # type: Dict[str, str]

    _REQUIRED = ("name", "count", "choice")  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    CUSTOM = "custom"  # type: str
    DEVICE = "device"  # type: str
    CPU = "cpu"  # type: str
    NPU = "npu"  # type: str
    NIC = "nic"  # type: str
    MEMORY = "memory"  # type: str
    PORT = "port"  # type: str
    SWITCH = "switch"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self, parent=None, choice=None, name=None, description=None, count=None
    ):
        super(Component, self).__init__()
        self._parent = parent
        self._set_property("name", name)
        self._set_property("description", description)
        self._set_property("count", count)
        if (
            "choice" in self._DEFAULTS
            and choice is None
            and self._DEFAULTS["choice"] in self._TYPES
        ):
            getattr(self, self._DEFAULTS["choice"])
        else:
            self._set_property("choice", choice)

    def set(self, name=None, description=None, count=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def custom(self):
        # type: () -> ComponentCustom
        """Factory property that returns an instance of the ComponentCustom class

        Placeholder for component that can be extended.

        Returns: ComponentCustom
        """
        return self._get_property("custom", ComponentCustom, self, "custom")

    @property
    def device(self):
        # type: () -> ComponentDevice
        """Factory property that returns an instance of the ComponentDevice class

        Placeholder for component that can be extended.

        Returns: ComponentDevice
        """
        return self._get_property("device", ComponentDevice, self, "device")

    @property
    def cpu(self):
        # type: () -> ComponentCpu
        """Factory property that returns an instance of the ComponentCpu class

        Placeholder for component that can be extended.

        Returns: ComponentCpu
        """
        return self._get_property("cpu", ComponentCpu, self, "cpu")

    @property
    def npu(self):
        # type: () -> ComponentNpu
        """Factory property that returns an instance of the ComponentNpu class

        Placeholder for component that can be extended.

        Returns: ComponentNpu
        """
        return self._get_property("npu", ComponentNpu, self, "npu")

    @property
    def nic(self):
        # type: () -> ComponentNic
        """Factory property that returns an instance of the ComponentNic class

        Placeholder for component that can be extended.

        Returns: ComponentNic
        """
        return self._get_property("nic", ComponentNic, self, "nic")

    @property
    def memory(self):
        # type: () -> ComponentMemory
        """Factory property that returns an instance of the ComponentMemory class

        Placeholder for component that can be extended.

        Returns: ComponentMemory
        """
        return self._get_property("memory", ComponentMemory, self, "memory")

    @property
    def port(self):
        # type: () -> ComponentPort
        """Factory property that returns an instance of the ComponentPort class

        Placeholder for component that can be extended.

        Returns: ComponentPort
        """
        return self._get_property("port", ComponentPort, self, "port")

    @property
    def switch(self):
        # type: () -> ComponentSwitch
        """Factory property that returns an instance of the ComponentSwitch class

        Placeholder for component that can be extended.

        Returns: ComponentSwitch
        """
        return self._get_property("switch", ComponentSwitch, self, "switch")

    @property
    def name(self):
        # type: () -> str
        """name getter

        Globally unique name of an object. It also serves as the primary key for arrays of objects.

        Returns: str
        """
        return self._get_property("name")

    @name.setter
    def name(self, value):
        """name setter

        Globally unique name of an object. It also serves as the primary key for arrays of objects.

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property name as None")
        self._set_property("name", value)

    @property
    def description(self):
        # type: () -> str
        """description getter

        A description of the component.

        Returns: str
        """
        return self._get_property("description")

    @description.setter
    def description(self, value):
        """description setter

        A description of the component.

        value: str
        """
        self._set_property("description", value)

    @property
    def count(self):
        # type: () -> int
        """count getter

        The maxiumim number of this component that will be contained by single device instance.. This property is used by the infragraph service in edge generation.

        Returns: int
        """
        return self._get_property("count")

    @count.setter
    def count(self, value):
        """count setter

        The maxiumim number of this component that will be contained by single device instance.. This property is used by the infragraph service in edge generation.

        value: int
        """
        if value is None:
            raise TypeError("Cannot set required property count as None")
        self._set_property("count", value)

    @property
    def choice(self):
        # type: () -> Union[Literal["cpu"], Literal["custom"], Literal["device"], Literal["memory"], Literal["nic"], Literal["npu"], Literal["port"], Literal["switch"]]
        """choice getter

        The type of component.. The `choice` value will be added to the graph node in the form of `type value` attribute.. - `custom` If the type of component is not listed as choice it can be defined using the custom object which includes type property that allows for custom type attribute on the graph node.. `device` This enum allows device to be composed of other devices. When this enum is selected the name of the component MUST be the name of device that exists in the Infrastructure.devices array.. `cpu` high level definition for cpu. `npu` high level definition for neural processing unit. `nic` high level definition for network interface card, for more detailed breakdowns create device representing specific type network interface card. `memory` high level definition for memory. `port` high level definitiion for an IO port. `switch` high level definition for an internal switch connecting components

        Returns: Union[Literal["cpu"], Literal["custom"], Literal["device"], Literal["memory"], Literal["nic"], Literal["npu"], Literal["port"], Literal["switch"]]
        """
        return self._get_property("choice")

    @choice.setter
    def choice(self, value):
        """choice setter

        The type of component.. The `choice` value will be added to the graph node in the form of `type value` attribute.. - `custom` If the type of component is not listed as choice it can be defined using the custom object which includes type property that allows for custom type attribute on the graph node.. `device` This enum allows device to be composed of other devices. When this enum is selected the name of the component MUST be the name of device that exists in the Infrastructure.devices array.. `cpu` high level definition for cpu. `npu` high level definition for neural processing unit. `nic` high level definition for network interface card, for more detailed breakdowns create device representing specific type network interface card. `memory` high level definition for memory. `port` high level definitiion for an IO port. `switch` high level definition for an internal switch connecting components

        value: Union[Literal["cpu"], Literal["custom"], Literal["device"], Literal["memory"], Literal["nic"], Literal["npu"], Literal["port"], Literal["switch"]]
        """
        if value is None:
            raise TypeError("Cannot set required property choice as None")
        self._set_property("choice", value)


class ComponentCustom(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "type": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ("type",)  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, type=None):
        super(ComponentCustom, self).__init__()
        self._parent = parent
        self._set_property("type", type)

    def set(self, type=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def type(self):
        # type: () -> str
        """type getter

        This property will be added to the graph node in the form of `type value` attribute.

        Returns: str
        """
        return self._get_property("type")

    @type.setter
    def type(self, value):
        """type setter

        This property will be added to the graph node in the form of `type value` attribute.

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property type as None")
        self._set_property("type", value)


class ComponentDevice(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {}  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(ComponentDevice, self).__init__()
        self._parent = parent


class ComponentCpu(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {}  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(ComponentCpu, self).__init__()
        self._parent = parent


class ComponentNpu(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {}  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(ComponentNpu, self).__init__()
        self._parent = parent


class ComponentNic(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {}  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(ComponentNic, self).__init__()
        self._parent = parent


class ComponentMemory(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {}  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(ComponentMemory, self).__init__()
        self._parent = parent


class ComponentPort(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {}  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(ComponentPort, self).__init__()
        self._parent = parent


class ComponentSwitch(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {}  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(ComponentSwitch, self).__init__()
        self._parent = parent


class ComponentIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(ComponentIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[Component, ComponentCpu, ComponentCustom, ComponentDevice, ComponentMemory, ComponentNic, ComponentNpu, ComponentPort, ComponentSwitch]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> ComponentIter
        return self._iter()

    def __next__(self):
        # type: () -> Component
        return self._next()

    def next(self):
        # type: () -> Component
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, Component):
            raise Exception("Item is not an instance of Component")

    def component(self, name=None, description=None, count=None):
        # type: (str,str,int) -> ComponentIter
        """Factory method that creates an instance of the Component class

        A container for describing component.. Component is contained in Device.

        Returns: ComponentIter
        """
        item = Component(
            parent=self._parent,
            choice=self._choice,
            name=name,
            description=description,
            count=count,
        )
        self._add(item)
        return self

    def add(self, name=None, description=None, count=None):
        # type: (str,str,int) -> Component
        """Add method that creates and returns an instance of the Component class

        A container for describing component.. Component is contained in Device.

        Returns: Component
        """
        item = Component(
            parent=self._parent,
            choice=self._choice,
            name=name,
            description=description,
            count=count,
        )
        self._add(item)
        return item


class Link(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "name": {
            "type": str,
            "pattern": r"^[\sa-zA-Z0-9-_()><\[\]]+$",
        },
        "description": {"type": str},
        "physical": {"type": "LinkPhysical"},
    }  # type: Dict[str, str]

    _REQUIRED = ("name",)  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, name=None, description=None):
        super(Link, self).__init__()
        self._parent = parent
        self._set_property("name", name)
        self._set_property("description", description)

    def set(self, name=None, description=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def name(self):
        # type: () -> str
        """name getter

        Globally unique name of an object. It also serves as the primary key for arrays of objects.

        Returns: str
        """
        return self._get_property("name")

    @name.setter
    def name(self, value):
        """name setter

        Globally unique name of an object. It also serves as the primary key for arrays of objects.

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property name as None")
        self._set_property("name", value)

    @property
    def description(self):
        # type: () -> str
        """description getter

        A description of the type of link.

        Returns: str
        """
        return self._get_property("description")

    @description.setter
    def description(self, value):
        """description setter

        A description of the type of link.

        value: str
        """
        self._set_property("description", value)

    @property
    def physical(self):
        # type: () -> LinkPhysical
        """physical getter

        A container for physical properties.

        Returns: LinkPhysical
        """
        return self._get_property("physical", LinkPhysical)


class LinkPhysical(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "bandwidth": {"type": "LinkPhysicalBandwidth"},
        "latency": {"type": "LinkPhysicalLatency"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(LinkPhysical, self).__init__()
        self._parent = parent

    @property
    def bandwidth(self):
        # type: () -> LinkPhysicalBandwidth
        """bandwidth getter

        A container for specific Link physical Properties.A container for specific Link physical Properties.A container for specific Link physical Properties.

        Returns: LinkPhysicalBandwidth
        """
        return self._get_property("bandwidth", LinkPhysicalBandwidth)

    @property
    def latency(self):
        # type: () -> LinkPhysicalLatency
        """latency getter

        A container for specific Link latency properties.A container for specific Link latency properties.A container for specific Link latency properties.

        Returns: LinkPhysicalLatency
        """
        return self._get_property("latency", LinkPhysicalLatency)


class LinkPhysicalBandwidth(OpenApiObject):
    __slots__ = ("_parent", "_choice")

    _TYPES = {
        "choice": {
            "type": str,
            "enum": [
                "gigabits_per_second",
                "gigabytes_per_second",
                "gigatransfers_per_second",
            ],
        },
        "gigabits_per_second": {"type": float},
        "gigabytes_per_second": {"type": float},
        "gigatransfers_per_second": {"type": float},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    GIGABITS_PER_SECOND = "gigabits_per_second"  # type: str
    GIGABYTES_PER_SECOND = "gigabytes_per_second"  # type: str
    GIGATRANSFERS_PER_SECOND = "gigatransfers_per_second"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self,
        parent=None,
        choice=None,
        gigabits_per_second=None,
        gigabytes_per_second=None,
        gigatransfers_per_second=None,
    ):
        super(LinkPhysicalBandwidth, self).__init__()
        self._parent = parent
        self._set_property("gigabits_per_second", gigabits_per_second)
        self._set_property("gigabytes_per_second", gigabytes_per_second)
        self._set_property("gigatransfers_per_second", gigatransfers_per_second)
        if (
            "choice" in self._DEFAULTS
            and choice is None
            and self._DEFAULTS["choice"] in self._TYPES
        ):
            getattr(self, self._DEFAULTS["choice"])
        else:
            self._set_property("choice", choice)

    def set(
        self,
        gigabits_per_second=None,
        gigabytes_per_second=None,
        gigatransfers_per_second=None,
    ):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def choice(self):
        # type: () -> Union[Literal["gigabits_per_second"], Literal["gigabytes_per_second"], Literal["gigatransfers_per_second"]]
        """choice getter

        TBD

        Returns: Union[Literal["gigabits_per_second"], Literal["gigabytes_per_second"], Literal["gigatransfers_per_second"]]
        """
        return self._get_property("choice")

    @choice.setter
    def choice(self, value):
        """choice setter

        TBD

        value: Union[Literal["gigabits_per_second"], Literal["gigabytes_per_second"], Literal["gigatransfers_per_second"]]
        """
        self._set_property("choice", value)

    @property
    def gigabits_per_second(self):
        # type: () -> float
        """gigabits_per_second getter

        Gigabits per second.

        Returns: float
        """
        return self._get_property("gigabits_per_second")

    @gigabits_per_second.setter
    def gigabits_per_second(self, value):
        """gigabits_per_second setter

        Gigabits per second.

        value: float
        """
        self._set_property("gigabits_per_second", value, "gigabits_per_second")

    @property
    def gigabytes_per_second(self):
        # type: () -> float
        """gigabytes_per_second getter

        Gigabytes per second.

        Returns: float
        """
        return self._get_property("gigabytes_per_second")

    @gigabytes_per_second.setter
    def gigabytes_per_second(self, value):
        """gigabytes_per_second setter

        Gigabytes per second.

        value: float
        """
        self._set_property("gigabytes_per_second", value, "gigabytes_per_second")

    @property
    def gigatransfers_per_second(self):
        # type: () -> float
        """gigatransfers_per_second getter

        Gigatrasfers per second.

        Returns: float
        """
        return self._get_property("gigatransfers_per_second")

    @gigatransfers_per_second.setter
    def gigatransfers_per_second(self, value):
        """gigatransfers_per_second setter

        Gigatrasfers per second.

        value: float
        """
        self._set_property(
            "gigatransfers_per_second", value, "gigatransfers_per_second"
        )


class LinkPhysicalLatency(OpenApiObject):
    __slots__ = ("_parent", "_choice")

    _TYPES = {
        "choice": {
            "type": str,
            "enum": [
                "ms",
                "us",
                "ns",
            ],
        },
        "ms": {"type": float},
        "us": {"type": float},
        "ns": {"type": float},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    MS = "ms"  # type: str
    US = "us"  # type: str
    NS = "ns"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, choice=None, ms=None, us=None, ns=None):
        super(LinkPhysicalLatency, self).__init__()
        self._parent = parent
        self._set_property("ms", ms)
        self._set_property("us", us)
        self._set_property("ns", ns)
        if (
            "choice" in self._DEFAULTS
            and choice is None
            and self._DEFAULTS["choice"] in self._TYPES
        ):
            getattr(self, self._DEFAULTS["choice"])
        else:
            self._set_property("choice", choice)

    def set(self, ms=None, us=None, ns=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def choice(self):
        # type: () -> Union[Literal["ms"], Literal["ns"], Literal["us"]]
        """choice getter

        TBD

        Returns: Union[Literal["ms"], Literal["ns"], Literal["us"]]
        """
        return self._get_property("choice")

    @choice.setter
    def choice(self, value):
        """choice setter

        TBD

        value: Union[Literal["ms"], Literal["ns"], Literal["us"]]
        """
        self._set_property("choice", value)

    @property
    def ms(self):
        # type: () -> float
        """ms getter

        Latency in milliseconds

        Returns: float
        """
        return self._get_property("ms")

    @ms.setter
    def ms(self, value):
        """ms setter

        Latency in milliseconds

        value: float
        """
        self._set_property("ms", value, "ms")

    @property
    def us(self):
        # type: () -> float
        """us getter

        Latency in microseconds.

        Returns: float
        """
        return self._get_property("us")

    @us.setter
    def us(self, value):
        """us setter

        Latency in microseconds.

        value: float
        """
        self._set_property("us", value, "us")

    @property
    def ns(self):
        # type: () -> float
        """ns getter

        Latency in nanoseconds.

        Returns: float
        """
        return self._get_property("ns")

    @ns.setter
    def ns(self, value):
        """ns setter

        Latency in nanoseconds.

        value: float
        """
        self._set_property("ns", value, "ns")


class LinkIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(LinkIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[Link]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> LinkIter
        return self._iter()

    def __next__(self):
        # type: () -> Link
        return self._next()

    def next(self):
        # type: () -> Link
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, Link):
            raise Exception("Item is not an instance of Link")

    def link(self, name=None, description=None):
        # type: (str,str) -> LinkIter
        """Factory method that creates an instance of the Link class

        A container for describing link used between components.

        Returns: LinkIter
        """
        item = Link(parent=self._parent, name=name, description=description)
        self._add(item)
        return self

    def add(self, name=None, description=None):
        # type: (str,str) -> Link
        """Add method that creates and returns an instance of the Link class

        A container for describing link used between components.

        Returns: Link
        """
        item = Link(parent=self._parent, name=name, description=description)
        self._add(item)
        return item


class DeviceEdge(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "ep1": {"type": "DeviceEndpoint"},
        "ep2": {"type": "DeviceEndpoint"},
        "scheme": {
            "type": str,
            "enum": [
                "one2one",
                "many2many",
                "ring",
            ],
        },
        "link": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ("ep1", "ep2", "link")  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    ONE2ONE = "one2one"  # type: str
    MANY2MANY = "many2many"  # type: str
    RING = "ring"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, scheme=None, link=None):
        super(DeviceEdge, self).__init__()
        self._parent = parent
        self._set_property("scheme", scheme)
        self._set_property("link", link)

    def set(self, scheme=None, link=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def ep1(self):
        # type: () -> DeviceEndpoint
        """ep1 getter

        An optional device and component that is the other endpoint of the edge

        Returns: DeviceEndpoint
        """
        return self._get_property("ep1", DeviceEndpoint)

    @property
    def ep2(self):
        # type: () -> DeviceEndpoint
        """ep2 getter

        An optional device and component that is the other endpoint of the edge

        Returns: DeviceEndpoint
        """
        return self._get_property("ep2", DeviceEndpoint)

    @property
    def scheme(self):
        # type: () -> Union[Literal["many2many"], Literal["one2one"], Literal["ring"]]
        """scheme getter

        The scheme that will be used to create edges between the endpoints ep1 and ep2.

        Returns: Union[Literal["many2many"], Literal["one2one"], Literal["ring"]]
        """
        return self._get_property("scheme")

    @scheme.setter
    def scheme(self, value):
        """scheme setter

        The scheme that will be used to create edges between the endpoints ep1 and ep2.

        value: Union[Literal["many2many"], Literal["one2one"], Literal["ring"]]
        """
        self._set_property("scheme", value)

    @property
    def link(self):
        # type: () -> str
        """link getter

        The name of link that defines additional characteristics of the edge.. The name MUST exist in the links array of the containing device.

        Returns: str
        """
        return self._get_property("link")

    @link.setter
    def link(self, value):
        """link setter

        The name of link that defines additional characteristics of the edge.. The name MUST exist in the links array of the containing device.

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property link as None")
        self._set_property("link", value)


class DeviceEndpoint(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "device": {"type": str},
        "component": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ("component",)  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, device=None, component=None):
        super(DeviceEndpoint, self).__init__()
        self._parent = parent
        self._set_property("device", device)
        self._set_property("component", component)

    def set(self, device=None, component=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def device(self):
        # type: () -> str
        """device getter

        An optional name of device that contains the component.. If the property is empty the name of the device is the parent of the edge object.. An endpoint will be generated for every device based on the count.

        Returns: str
        """
        return self._get_property("device")

    @device.setter
    def device(self, value):
        """device setter

        An optional name of device that contains the component.. If the property is empty the name of the device is the parent of the edge object.. An endpoint will be generated for every device based on the count.

        value: str
        """
        self._set_property("device", value)

    @property
    def component(self):
        # type: () -> str
        """component getter

        The name of component that exists in the containing device. and the indexes of the component.. The indexes MUST be specified using python slice notation.. example: cx5[0:2]

        Returns: str
        """
        return self._get_property("component")

    @component.setter
    def component(self, value):
        """component setter

        The name of component that exists in the containing device. and the indexes of the component.. The indexes MUST be specified using python slice notation.. example: cx5[0:2]

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property component as None")
        self._set_property("component", value)


class DeviceEdgeIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(DeviceEdgeIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[DeviceEdge]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> DeviceEdgeIter
        return self._iter()

    def __next__(self):
        # type: () -> DeviceEdge
        return self._next()

    def next(self):
        # type: () -> DeviceEdge
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, DeviceEdge):
            raise Exception("Item is not an instance of DeviceEdge")

    def edge(self, scheme=None, link=None):
        # type: (Union[Literal["many2many"], Literal["one2one"], Literal["ring"]],str) -> DeviceEdgeIter
        """Factory method that creates an instance of the DeviceEdge class

        TBD

        Returns: DeviceEdgeIter
        """
        item = DeviceEdge(parent=self._parent, scheme=scheme, link=link)
        self._add(item)
        return self

    def add(self, scheme=None, link=None):
        # type: (Union[Literal["many2many"], Literal["one2one"], Literal["ring"]],str) -> DeviceEdge
        """Add method that creates and returns an instance of the DeviceEdge class

        TBD

        Returns: DeviceEdge
        """
        item = DeviceEdge(parent=self._parent, scheme=scheme, link=link)
        self._add(item)
        return item


class DeviceIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(DeviceIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[Device]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> DeviceIter
        return self._iter()

    def __next__(self):
        # type: () -> Device
        return self._next()

    def next(self):
        # type: () -> Device
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, Device):
            raise Exception("Item is not an instance of Device")

    def device(self, name=None, description=None):
        # type: (str,str) -> DeviceIter
        """Factory method that creates an instance of the Device class

        A subgraph container for device and its components, links and edges.. The edges form subgraph of the device.

        Returns: DeviceIter
        """
        item = Device(parent=self._parent, name=name, description=description)
        self._add(item)
        return self

    def add(self, name=None, description=None):
        # type: (str,str) -> Device
        """Add method that creates and returns an instance of the Device class

        A subgraph container for device and its components, links and edges.. The edges form subgraph of the device.

        Returns: Device
        """
        item = Device(parent=self._parent, name=name, description=description)
        self._add(item)
        return item


class Instance(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "name": {
            "type": str,
            "pattern": r"^[\sa-zA-Z0-9-_()><\[\]]+$",
        },
        "description": {"type": str},
        "device": {"type": str},
        "count": {
            "type": int,
            "format": "int32",
        },
    }  # type: Dict[str, str]

    _REQUIRED = ("name", "device", "count")  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self, parent=None, name=None, description=None, device=None, count=None
    ):
        super(Instance, self).__init__()
        self._parent = parent
        self._set_property("name", name)
        self._set_property("description", description)
        self._set_property("device", device)
        self._set_property("count", count)

    def set(self, name=None, description=None, device=None, count=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def name(self):
        # type: () -> str
        """name getter

        An alias for the device that MUST be used in the Infrastructure edge object.. Globally unique name of an object. It also serves as the primary key for arrays of objects.

        Returns: str
        """
        return self._get_property("name")

    @name.setter
    def name(self, value):
        """name setter

        An alias for the device that MUST be used in the Infrastructure edge object.. Globally unique name of an object. It also serves as the primary key for arrays of objects.

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property name as None")
        self._set_property("name", value)

    @property
    def description(self):
        # type: () -> str
        """description getter

        A description of the instance.

        Returns: str
        """
        return self._get_property("description")

    @description.setter
    def description(self, value):
        """description setter

        A description of the instance.

        value: str
        """
        self._set_property("description", value)

    @property
    def device(self):
        # type: () -> str
        """device getter

        The name of device that MUST exist in the array of Infrastructure devices.

        Returns: str
        """
        return self._get_property("device")

    @device.setter
    def device(self, value):
        """device setter

        The name of device that MUST exist in the array of Infrastructure devices.

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property device as None")
        self._set_property("device", value)

    @property
    def count(self):
        # type: () -> int
        """count getter

        The maximum number of instances that will be created as nodes in the graph.. Not all the instances need to be used in the graph edges.

        Returns: int
        """
        return self._get_property("count")

    @count.setter
    def count(self, value):
        """count setter

        The maximum number of instances that will be created as nodes in the graph.. Not all the instances need to be used in the graph edges.

        value: int
        """
        if value is None:
            raise TypeError("Cannot set required property count as None")
        self._set_property("count", value)


class InstanceIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(InstanceIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[Instance]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> InstanceIter
        return self._iter()

    def __next__(self):
        # type: () -> Instance
        return self._next()

    def next(self):
        # type: () -> Instance
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, Instance):
            raise Exception("Item is not an instance of Instance")

    def instance(self, name=None, description=None, device=None, count=None):
        # type: (str,str,str,int) -> InstanceIter
        """Factory method that creates an instance of the Instance class

        TBD

        Returns: InstanceIter
        """
        item = Instance(
            parent=self._parent,
            name=name,
            description=description,
            device=device,
            count=count,
        )
        self._add(item)
        return self

    def add(self, name=None, description=None, device=None, count=None):
        # type: (str,str,str,int) -> Instance
        """Add method that creates and returns an instance of the Instance class

        TBD

        Returns: Instance
        """
        item = Instance(
            parent=self._parent,
            name=name,
            description=description,
            device=device,
            count=count,
        )
        self._add(item)
        return item


class InfrastructureEdge(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "ep1": {"type": "InfrastructureEndpoint"},
        "ep2": {"type": "InfrastructureEndpoint"},
        "scheme": {
            "type": str,
            "enum": [
                "one2one",
                "many2many",
                "ring",
            ],
        },
        "link": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ("ep1", "ep2", "link")  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    ONE2ONE = "one2one"  # type: str
    MANY2MANY = "many2many"  # type: str
    RING = "ring"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, scheme=None, link=None):
        super(InfrastructureEdge, self).__init__()
        self._parent = parent
        self._set_property("scheme", scheme)
        self._set_property("link", link)

    def set(self, scheme=None, link=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def ep1(self):
        # type: () -> InfrastructureEndpoint
        """ep1 getter

        A device and component that is one endpoint of the edge

        Returns: InfrastructureEndpoint
        """
        return self._get_property("ep1", InfrastructureEndpoint)

    @property
    def ep2(self):
        # type: () -> InfrastructureEndpoint
        """ep2 getter

        A device and component that is the other endpoint of the edge

        Returns: InfrastructureEndpoint
        """
        return self._get_property("ep2", InfrastructureEndpoint)

    @property
    def scheme(self):
        # type: () -> Union[Literal["many2many"], Literal["one2one"], Literal["ring"]]
        """scheme getter

        The scheme that will be used to create edges between the endpoints ep1 and ep2.

        Returns: Union[Literal["many2many"], Literal["one2one"], Literal["ring"]]
        """
        return self._get_property("scheme")

    @scheme.setter
    def scheme(self, value):
        """scheme setter

        The scheme that will be used to create edges between the endpoints ep1 and ep2.

        value: Union[Literal["many2many"], Literal["one2one"], Literal["ring"]]
        """
        self._set_property("scheme", value)

    @property
    def link(self):
        # type: () -> str
        """link getter

        The name of link that defines additional characteristics of the edge.. The name MUST exist in the links array of the infrastructure.

        Returns: str
        """
        return self._get_property("link")

    @link.setter
    def link(self, value):
        """link setter

        The name of link that defines additional characteristics of the edge.. The name MUST exist in the links array of the infrastructure.

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property link as None")
        self._set_property("link", value)


class InfrastructureEndpoint(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "instance": {"type": str},
        "component": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ("instance", "component")  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, instance=None, component=None):
        super(InfrastructureEndpoint, self).__init__()
        self._parent = parent
        self._set_property("instance", instance)
        self._set_property("component", component)

    def set(self, instance=None, component=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def instance(self):
        # type: () -> str
        """instance getter

        A name that matches the Instance.name property of an instance object that MUST exist in the infrastructure instances array.. The instance object yields:. a device name that contains the component and MUST exist in the infrastructure devices. a count that is the maximum to be used in the slice notation. The indexes MUST be specified using python slice notation.. example: host[0:2]

        Returns: str
        """
        return self._get_property("instance")

    @instance.setter
    def instance(self, value):
        """instance setter

        A name that matches the Instance.name property of an instance object that MUST exist in the infrastructure instances array.. The instance object yields:. a device name that contains the component and MUST exist in the infrastructure devices. a count that is the maximum to be used in the slice notation. The indexes MUST be specified using python slice notation.. example: host[0:2]

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property instance as None")
        self._set_property("instance", value)

    @property
    def component(self):
        # type: () -> str
        """component getter

        The name of component that MUST exist in the Instance.device specified by the instance object in the Infrastructure.instances array.. The indexes MUST be specified using python slice notation.. example: npu[0:2]

        Returns: str
        """
        return self._get_property("component")

    @component.setter
    def component(self, value):
        """component setter

        The name of component that MUST exist in the Instance.device specified by the instance object in the Infrastructure.instances array.. The indexes MUST be specified using python slice notation.. example: npu[0:2]

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property component as None")
        self._set_property("component", value)


class InfrastructureEdgeIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(InfrastructureEdgeIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[InfrastructureEdge]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> InfrastructureEdgeIter
        return self._iter()

    def __next__(self):
        # type: () -> InfrastructureEdge
        return self._next()

    def next(self):
        # type: () -> InfrastructureEdge
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, InfrastructureEdge):
            raise Exception("Item is not an instance of InfrastructureEdge")

    def edge(self, scheme=None, link=None):
        # type: (Union[Literal["many2many"], Literal["one2one"], Literal["ring"]],str) -> InfrastructureEdgeIter
        """Factory method that creates an instance of the InfrastructureEdge class

        TBD

        Returns: InfrastructureEdgeIter
        """
        item = InfrastructureEdge(parent=self._parent, scheme=scheme, link=link)
        self._add(item)
        return self

    def add(self, scheme=None, link=None):
        # type: (Union[Literal["many2many"], Literal["one2one"], Literal["ring"]],str) -> InfrastructureEdge
        """Add method that creates and returns an instance of the InfrastructureEdge class

        TBD

        Returns: InfrastructureEdge
        """
        item = InfrastructureEdge(parent=self._parent, scheme=scheme, link=link)
        self._add(item)
        return item


class Warning(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "warnings": {
            "type": list,
            "itemtype": str,
        },
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, warnings=None):
        super(Warning, self).__init__()
        self._parent = parent
        self._set_property("warnings", warnings)

    def set(self, warnings=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def warnings(self):
        # type: () -> List[str]
        """warnings getter

        A list of any system specific warnings that have occurred while. executing the request.

        Returns: List[str]
        """
        return self._get_property("warnings")

    @warnings.setter
    def warnings(self, value):
        """warnings setter

        A list of any system specific warnings that have occurred while. executing the request.

        value: List[str]
        """
        self._set_property("warnings", value)


class Error(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "code": {
            "type": int,
            "format": "int32",
        },
        "kind": {
            "type": str,
            "enum": [
                "validation",
                "internal",
            ],
        },
        "errors": {
            "type": list,
            "itemtype": str,
        },
    }  # type: Dict[str, str]

    _REQUIRED = ("code", "errors")  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    VALIDATION = "validation"  # type: str
    INTERNAL = "internal"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, code=None, kind=None, errors=None):
        super(Error, self).__init__()
        self._parent = parent
        self._set_property("code", code)
        self._set_property("kind", kind)
        self._set_property("errors", errors)

    def set(self, code=None, kind=None, errors=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def code(self):
        # type: () -> int
        """code getter

        Numeric status code based on the underlying transport being used.. The API server MUST set this code explicitly based on following references:. HTTP 4xx errors: https://datatracker.ietf.org/doc/html/rfc9110#section-15.5. HTTP 5xx errors: https://datatracker.ietf.org/doc/html/rfc9110#section-15.6. gRPC errors: https://grpc.github.io/grpc/core/md_doc_statuscodes.html

        Returns: int
        """
        return self._get_property("code")

    @code.setter
    def code(self, value):
        """code setter

        Numeric status code based on the underlying transport being used.. The API server MUST set this code explicitly based on following references:. HTTP 4xx errors: https://datatracker.ietf.org/doc/html/rfc9110#section-15.5. HTTP 5xx errors: https://datatracker.ietf.org/doc/html/rfc9110#section-15.6. gRPC errors: https://grpc.github.io/grpc/core/md_doc_statuscodes.html

        value: int
        """
        if value is None:
            raise TypeError("Cannot set required property code as None")
        self._set_property("code", value)

    @property
    def kind(self):
        # type: () -> Union[Literal["internal"], Literal["validation"]]
        """kind getter

        Classification of error originating from within API server that may not be mapped to the value in `code`.. Absence of this field may indicate that the error did not originate from within API server.

        Returns: Union[Literal["internal"], Literal["validation"]]
        """
        return self._get_property("kind")

    @kind.setter
    def kind(self, value):
        """kind setter

        Classification of error originating from within API server that may not be mapped to the value in `code`.. Absence of this field may indicate that the error did not originate from within API server.

        value: Union[Literal["internal"], Literal["validation"]]
        """
        self._set_property("kind", value)

    @property
    def errors(self):
        # type: () -> List[str]
        """errors getter

        List of error messages generated while executing the request.

        Returns: List[str]
        """
        return self._get_property("errors")

    @errors.setter
    def errors(self, value):
        """errors setter

        List of error messages generated while executing the request.

        value: List[str]
        """
        if value is None:
            raise TypeError("Cannot set required property errors as None")
        self._set_property("errors", value)


class GraphRequest(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "format": {
            "type": str,
            "enum": [
                "networkx",
            ],
        },
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    NETWORKX = "networkx"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, format=None):
        super(GraphRequest, self).__init__()
        self._parent = parent
        self._set_property("format", format)

    def set(self, format=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def format(self):
        # type: () -> Union[Literal["networkx"]]
        """format getter

        The format that the graph will be returned in.

        Returns: Union[Literal["networkx"]]
        """
        return self._get_property("format")

    @format.setter
    def format(self, value):
        """format setter

        The format that the graph will be returned in.

        value: Union[Literal["networkx"]]
        """
        self._set_property("format", value)


class GraphContent(OpenApiObject):
    __slots__ = ("_parent", "_choice")

    _TYPES = {
        "choice": {
            "type": str,
            "enum": [
                "networkx",
            ],
        },
        "networkx": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    NETWORKX = "networkx"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, choice=None, networkx=None):
        super(GraphContent, self).__init__()
        self._parent = parent
        self._set_property("networkx", networkx)
        if (
            "choice" in self._DEFAULTS
            and choice is None
            and self._DEFAULTS["choice"] in self._TYPES
        ):
            getattr(self, self._DEFAULTS["choice"])
        else:
            self._set_property("choice", choice)

    def set(self, networkx=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def choice(self):
        # type: () -> Union[Literal["networkx"]]
        """choice getter

        TBD

        Returns: Union[Literal["networkx"]]
        """
        return self._get_property("choice")

    @choice.setter
    def choice(self, value):
        """choice setter

        TBD

        value: Union[Literal["networkx"]]
        """
        self._set_property("choice", value)

    @property
    def networkx(self):
        # type: () -> str
        """networkx getter

        This contains the returned graph content formatted as networkx yaml string.

        Returns: str
        """
        return self._get_property("networkx")

    @networkx.setter
    def networkx(self, value):
        """networkx setter

        This contains the returned graph content formatted as networkx yaml string.

        value: str
        """
        self._set_property("networkx", value, "networkx")


class QueryRequest(OpenApiObject):
    __slots__ = ("_parent", "_choice")

    _TYPES = {
        "choice": {
            "type": str,
            "enum": [
                "node_filters",
                "shortest_path_filters",
            ],
        },
        "node_filters": {"type": "QueryNodeFilterIter"},
        "shortest_path_filters": {"type": "QueryShortestPathFilterIter"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    NODE_FILTERS = "node_filters"  # type: str
    SHORTEST_PATH_FILTERS = "shortest_path_filters"  # type: str

    _STATUS = {
        "shortest_path_filters": "shortest_path_filters property in schema QueryRequest is under_review, Proposal to abstract the shortest path interface to the graph.",
    }  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, choice=None):
        super(QueryRequest, self).__init__()
        self._parent = parent
        if (
            "choice" in self._DEFAULTS
            and choice is None
            and self._DEFAULTS["choice"] in self._TYPES
        ):
            getattr(self, self._DEFAULTS["choice"])
        else:
            self._set_property("choice", choice)

    @property
    def choice(self):
        # type: () -> Union[Literal["node_filters"], Literal["shortest_path_filters"]]
        """choice getter

        TBD

        Returns: Union[Literal["node_filters"], Literal["shortest_path_filters"]]
        """
        return self._get_property("choice")

    @choice.setter
    def choice(self, value):
        """choice setter

        TBD

        value: Union[Literal["node_filters"], Literal["shortest_path_filters"]]
        """
        self._set_property("choice", value)

    @property
    def node_filters(self):
        # type: () -> QueryNodeFilterIter
        """node_filters getter

        TBD

        Returns: QueryNodeFilterIter
        """
        return self._get_property(
            "node_filters", QueryNodeFilterIter, self._parent, self._choice
        )

    @property
    def shortest_path_filters(self):
        # type: () -> QueryShortestPathFilterIter
        """shortest_path_filters getter

        Under Review: Proposal to abstract the shortest path interface to the graph.. Add shortest path filters to retrive the shortest path between source and destination nodes

        Returns: QueryShortestPathFilterIter
        """
        return self._get_property(
            "shortest_path_filters",
            QueryShortestPathFilterIter,
            self._parent,
            self._choice,
        )


class QueryNodeFilter(OpenApiObject):
    __slots__ = ("_parent", "_choice")

    _TYPES = {
        "name": {"type": str},
        "choice": {
            "type": str,
            "enum": [
                "attribute_filter",
                "id_filter",
            ],
        },
        "attribute_filter": {"type": "QueryAttribute"},
        "id_filter": {"type": "QueryNodeId"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    ATTRIBUTE_FILTER = "attribute_filter"  # type: str
    ID_FILTER = "id_filter"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, choice=None, name=None):
        super(QueryNodeFilter, self).__init__()
        self._parent = parent
        self._set_property("name", name)
        if (
            "choice" in self._DEFAULTS
            and choice is None
            and self._DEFAULTS["choice"] in self._TYPES
        ):
            getattr(self, self._DEFAULTS["choice"])
        else:
            self._set_property("choice", choice)

    def set(self, name=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def attribute_filter(self):
        # type: () -> QueryAttribute
        """Factory property that returns an instance of the QueryAttribute class

        TBD

        Returns: QueryAttribute
        """
        return self._get_property(
            "attribute_filter", QueryAttribute, self, "attribute_filter"
        )

    @property
    def id_filter(self):
        # type: () -> QueryNodeId
        """Factory property that returns an instance of the QueryNodeId class

        TBD

        Returns: QueryNodeId
        """
        return self._get_property("id_filter", QueryNodeId, self, "id_filter")

    @property
    def name(self):
        # type: () -> str
        """name getter

        TBD

        Returns: str
        """
        return self._get_property("name")

    @name.setter
    def name(self, value):
        """name setter

        TBD

        value: str
        """
        self._set_property("name", value)

    @property
    def choice(self):
        # type: () -> Union[Literal["attribute_filter"], Literal["id_filter"]]
        """choice getter

        TBD

        Returns: Union[Literal["attribute_filter"], Literal["id_filter"]]
        """
        return self._get_property("choice")

    @choice.setter
    def choice(self, value):
        """choice setter

        TBD

        value: Union[Literal["attribute_filter"], Literal["id_filter"]]
        """
        self._set_property("choice", value)


class QueryAttribute(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "name": {"type": str},
        "operator": {
            "type": str,
            "enum": [
                "contains",
                "eq",
                "regex",
            ],
        },
        "value": {"type": str},
        "logic": {
            "type": str,
            "enum": [
                "and",
                "or",
            ],
        },
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    CONTAINS = "contains"  # type: str
    EQ = "eq"  # type: str
    REGEX = "regex"  # type: str

    AND = "and"  # type: str
    OR = "or"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, name=None, operator=None, value=None, logic=None):
        super(QueryAttribute, self).__init__()
        self._parent = parent
        self._set_property("name", name)
        self._set_property("operator", operator)
        self._set_property("value", value)
        self._set_property("logic", logic)

    def set(self, name=None, operator=None, value=None, logic=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def name(self):
        # type: () -> str
        """name getter

        TBD

        Returns: str
        """
        return self._get_property("name")

    @name.setter
    def name(self, value):
        """name setter

        TBD

        value: str
        """
        self._set_property("name", value)

    @property
    def operator(self):
        # type: () -> Union[Literal["contains"], Literal["eq"], Literal["regex"]]
        """operator getter

        TBD

        Returns: Union[Literal["contains"], Literal["eq"], Literal["regex"]]
        """
        return self._get_property("operator")

    @operator.setter
    def operator(self, value):
        """operator setter

        TBD

        value: Union[Literal["contains"], Literal["eq"], Literal["regex"]]
        """
        self._set_property("operator", value)

    @property
    def value(self):
        # type: () -> str
        """value getter

        TBD

        Returns: str
        """
        return self._get_property("value")

    @value.setter
    def value(self, value):
        """value setter

        TBD

        value: str
        """
        self._set_property("value", value)

    @property
    def logic(self):
        # type: () -> Union[Literal["and"], Literal["or"]]
        """logic getter

        TBD

        Returns: Union[Literal["and"], Literal["or"]]
        """
        return self._get_property("logic")

    @logic.setter
    def logic(self, value):
        """logic setter

        TBD

        value: Union[Literal["and"], Literal["or"]]
        """
        self._set_property("logic", value)


class QueryNodeId(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "operator": {
            "type": str,
            "enum": [
                "contains",
                "eq",
                "regex",
            ],
        },
        "value": {"type": str},
        "logic": {
            "type": str,
            "enum": [
                "and",
                "or",
            ],
        },
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    CONTAINS = "contains"  # type: str
    EQ = "eq"  # type: str
    REGEX = "regex"  # type: str

    AND = "and"  # type: str
    OR = "or"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, operator=None, value=None, logic=None):
        super(QueryNodeId, self).__init__()
        self._parent = parent
        self._set_property("operator", operator)
        self._set_property("value", value)
        self._set_property("logic", logic)

    def set(self, operator=None, value=None, logic=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def operator(self):
        # type: () -> Union[Literal["contains"], Literal["eq"], Literal["regex"]]
        """operator getter

        TBD

        Returns: Union[Literal["contains"], Literal["eq"], Literal["regex"]]
        """
        return self._get_property("operator")

    @operator.setter
    def operator(self, value):
        """operator setter

        TBD

        value: Union[Literal["contains"], Literal["eq"], Literal["regex"]]
        """
        self._set_property("operator", value)

    @property
    def value(self):
        # type: () -> str
        """value getter

        TBD

        Returns: str
        """
        return self._get_property("value")

    @value.setter
    def value(self, value):
        """value setter

        TBD

        value: str
        """
        self._set_property("value", value)

    @property
    def logic(self):
        # type: () -> Union[Literal["and"], Literal["or"]]
        """logic getter

        TBD

        Returns: Union[Literal["and"], Literal["or"]]
        """
        return self._get_property("logic")

    @logic.setter
    def logic(self, value):
        """logic setter

        TBD

        value: Union[Literal["and"], Literal["or"]]
        """
        self._set_property("logic", value)


class QueryNodeFilterIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(QueryNodeFilterIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[QueryAttribute, QueryNodeFilter, QueryNodeId]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> QueryNodeFilterIter
        return self._iter()

    def __next__(self):
        # type: () -> QueryNodeFilter
        return self._next()

    def next(self):
        # type: () -> QueryNodeFilter
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, QueryNodeFilter):
            raise Exception("Item is not an instance of QueryNodeFilter")

    def querynodefilter(self, name=None):
        # type: (str) -> QueryNodeFilterIter
        """Factory method that creates an instance of the QueryNodeFilter class

        TBD

        Returns: QueryNodeFilterIter
        """
        item = QueryNodeFilter(parent=self._parent, choice=self._choice, name=name)
        self._add(item)
        return self

    def add(self, name=None):
        # type: (str) -> QueryNodeFilter
        """Add method that creates and returns an instance of the QueryNodeFilter class

        TBD

        Returns: QueryNodeFilter
        """
        item = QueryNodeFilter(parent=self._parent, choice=self._choice, name=name)
        self._add(item)
        return item


class QueryShortestPathFilter(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "name": {"type": str},
        "source": {"type": str},
        "destination": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ("name", "source", "destination")  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, name=None, source=None, destination=None):
        super(QueryShortestPathFilter, self).__init__()
        self._parent = parent
        self._set_property("name", name)
        self._set_property("source", source)
        self._set_property("destination", destination)

    def set(self, name=None, source=None, destination=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def name(self):
        # type: () -> str
        """name getter

        TBD

        Returns: str
        """
        return self._get_property("name")

    @name.setter
    def name(self, value):
        """name setter

        TBD

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property name as None")
        self._set_property("name", value)

    @property
    def source(self):
        # type: () -> str
        """source getter

        TBD

        Returns: str
        """
        return self._get_property("source")

    @source.setter
    def source(self, value):
        """source setter

        TBD

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property source as None")
        self._set_property("source", value)

    @property
    def destination(self):
        # type: () -> str
        """destination getter

        TBD

        Returns: str
        """
        return self._get_property("destination")

    @destination.setter
    def destination(self, value):
        """destination setter

        TBD

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property destination as None")
        self._set_property("destination", value)


class QueryShortestPathFilterIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(QueryShortestPathFilterIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[QueryShortestPathFilter]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> QueryShortestPathFilterIter
        return self._iter()

    def __next__(self):
        # type: () -> QueryShortestPathFilter
        return self._next()

    def next(self):
        # type: () -> QueryShortestPathFilter
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, QueryShortestPathFilter):
            raise Exception("Item is not an instance of QueryShortestPathFilter")

    def queryshortestpathfilter(self, name=None, source=None, destination=None):
        # type: (str,str,str) -> QueryShortestPathFilterIter
        """Factory method that creates an instance of the QueryShortestPathFilter class

        TBD

        Returns: QueryShortestPathFilterIter
        """
        item = QueryShortestPathFilter(
            parent=self._parent, name=name, source=source, destination=destination
        )
        self._add(item)
        return self

    def add(self, name=None, source=None, destination=None):
        # type: (str,str,str) -> QueryShortestPathFilter
        """Add method that creates and returns an instance of the QueryShortestPathFilter class

        TBD

        Returns: QueryShortestPathFilter
        """
        item = QueryShortestPathFilter(
            parent=self._parent, name=name, source=source, destination=destination
        )
        self._add(item)
        return item


class QueryResponseContent(OpenApiObject):
    __slots__ = ("_parent", "_choice")

    _TYPES = {
        "choice": {
            "type": str,
            "enum": [
                "node_matches",
                "shortest_path_matches",
            ],
        },
        "node_matches": {"type": "QueryResponseItemIter"},
        "shortest_path_matches": {"type": "QueryShortestPathItemIter"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    NODE_MATCHES = "node_matches"  # type: str
    SHORTEST_PATH_MATCHES = "shortest_path_matches"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, choice=None):
        super(QueryResponseContent, self).__init__()
        self._parent = parent
        if (
            "choice" in self._DEFAULTS
            and choice is None
            and self._DEFAULTS["choice"] in self._TYPES
        ):
            getattr(self, self._DEFAULTS["choice"])
        else:
            self._set_property("choice", choice)

    @property
    def choice(self):
        # type: () -> Union[Literal["node_matches"], Literal["shortest_path_matches"]]
        """choice getter

        TBD

        Returns: Union[Literal["node_matches"], Literal["shortest_path_matches"]]
        """
        return self._get_property("choice")

    @choice.setter
    def choice(self, value):
        """choice setter

        TBD

        value: Union[Literal["node_matches"], Literal["shortest_path_matches"]]
        """
        self._set_property("choice", value)

    @property
    def node_matches(self):
        # type: () -> QueryResponseItemIter
        """node_matches getter

        TBD

        Returns: QueryResponseItemIter
        """
        return self._get_property(
            "node_matches", QueryResponseItemIter, self._parent, self._choice
        )

    @property
    def shortest_path_matches(self):
        # type: () -> QueryShortestPathItemIter
        """shortest_path_matches getter

        TBD

        Returns: QueryShortestPathItemIter
        """
        return self._get_property(
            "shortest_path_matches",
            QueryShortestPathItemIter,
            self._parent,
            self._choice,
        )


class QueryResponseItem(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "id": {"type": str},
        "attributes": {"type": "NameValueIter"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, id=None):
        super(QueryResponseItem, self).__init__()
        self._parent = parent
        self._set_property("id", id)

    def set(self, id=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def id(self):
        # type: () -> str
        """id getter

        TBD

        Returns: str
        """
        return self._get_property("id")

    @id.setter
    def id(self, value):
        """id setter

        TBD

        value: str
        """
        self._set_property("id", value)

    @property
    def attributes(self):
        # type: () -> NameValueIter
        """attributes getter

        TBD

        Returns: NameValueIter
        """
        return self._get_property(
            "attributes", NameValueIter, self._parent, self._choice
        )


class NameValue(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "name": {"type": str},
        "value": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, name=None, value=None):
        super(NameValue, self).__init__()
        self._parent = parent
        self._set_property("name", name)
        self._set_property("value", value)

    def set(self, name=None, value=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def name(self):
        # type: () -> str
        """name getter

        TBD

        Returns: str
        """
        return self._get_property("name")

    @name.setter
    def name(self, value):
        """name setter

        TBD

        value: str
        """
        self._set_property("name", value)

    @property
    def value(self):
        # type: () -> str
        """value getter

        TBD

        Returns: str
        """
        return self._get_property("value")

    @value.setter
    def value(self, value):
        """value setter

        TBD

        value: str
        """
        self._set_property("value", value)


class NameValueIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(NameValueIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[NameValue]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> NameValueIter
        return self._iter()

    def __next__(self):
        # type: () -> NameValue
        return self._next()

    def next(self):
        # type: () -> NameValue
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, NameValue):
            raise Exception("Item is not an instance of NameValue")

    def namevalue(self, name=None, value=None):
        # type: (str,str) -> NameValueIter
        """Factory method that creates an instance of the NameValue class

        TBD

        Returns: NameValueIter
        """
        item = NameValue(parent=self._parent, name=name, value=value)
        self._add(item)
        return self

    def add(self, name=None, value=None):
        # type: (str,str) -> NameValue
        """Add method that creates and returns an instance of the NameValue class

        TBD

        Returns: NameValue
        """
        item = NameValue(parent=self._parent, name=name, value=value)
        self._add(item)
        return item


class QueryResponseItemIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(QueryResponseItemIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[QueryResponseItem]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> QueryResponseItemIter
        return self._iter()

    def __next__(self):
        # type: () -> QueryResponseItem
        return self._next()

    def next(self):
        # type: () -> QueryResponseItem
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, QueryResponseItem):
            raise Exception("Item is not an instance of QueryResponseItem")

    def queryresponseitem(self, id=None):
        # type: (str) -> QueryResponseItemIter
        """Factory method that creates an instance of the QueryResponseItem class

        TBD

        Returns: QueryResponseItemIter
        """
        item = QueryResponseItem(parent=self._parent, id=id)
        self._add(item)
        return self

    def add(self, id=None):
        # type: (str) -> QueryResponseItem
        """Add method that creates and returns an instance of the QueryResponseItem class

        TBD

        Returns: QueryResponseItem
        """
        item = QueryResponseItem(parent=self._parent, id=id)
        self._add(item)
        return item


class QueryShortestPathItem(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "name": {"type": str},
        "nodes": {
            "type": list,
            "itemtype": str,
        },
    }  # type: Dict[str, str]

    _REQUIRED = ("name", "nodes")  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, name=None, nodes=None):
        super(QueryShortestPathItem, self).__init__()
        self._parent = parent
        self._set_property("name", name)
        self._set_property("nodes", nodes)

    def set(self, name=None, nodes=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def name(self):
        # type: () -> str
        """name getter

        Name of the shortest path filter

        Returns: str
        """
        return self._get_property("name")

    @name.setter
    def name(self, value):
        """name setter

        Name of the shortest path filter

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property name as None")
        self._set_property("name", value)

    @property
    def nodes(self):
        # type: () -> List[str]
        """nodes getter

        An array of node ids that make up the shortest path

        Returns: List[str]
        """
        return self._get_property("nodes")

    @nodes.setter
    def nodes(self, value):
        """nodes setter

        An array of node ids that make up the shortest path

        value: List[str]
        """
        if value is None:
            raise TypeError("Cannot set required property nodes as None")
        self._set_property("nodes", value)


class QueryShortestPathItemIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(QueryShortestPathItemIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[QueryShortestPathItem]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> QueryShortestPathItemIter
        return self._iter()

    def __next__(self):
        # type: () -> QueryShortestPathItem
        return self._next()

    def next(self):
        # type: () -> QueryShortestPathItem
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, QueryShortestPathItem):
            raise Exception("Item is not an instance of QueryShortestPathItem")

    def queryshortestpathitem(self, name=None, nodes=None):
        # type: (str,List[str]) -> QueryShortestPathItemIter
        """Factory method that creates an instance of the QueryShortestPathItem class

        TBD

        Returns: QueryShortestPathItemIter
        """
        item = QueryShortestPathItem(parent=self._parent, name=name, nodes=nodes)
        self._add(item)
        return self

    def add(self, name=None, nodes=None):
        # type: (str,List[str]) -> QueryShortestPathItem
        """Add method that creates and returns an instance of the QueryShortestPathItem class

        TBD

        Returns: QueryShortestPathItem
        """
        item = QueryShortestPathItem(parent=self._parent, name=name, nodes=nodes)
        self._add(item)
        return item


class AnnotateRequest(OpenApiObject):
    __slots__ = ("_parent", "_choice")

    _TYPES = {
        "choice": {
            "type": str,
            "enum": [
                "nodes",
                "edges",
            ],
        },
        "nodes": {"type": "AnnotationNodeIter"},
        "edges": {"type": "AnnotationEdgeIter"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    NODES = "nodes"  # type: str
    EDGES = "edges"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, choice=None):
        super(AnnotateRequest, self).__init__()
        self._parent = parent
        if (
            "choice" in self._DEFAULTS
            and choice is None
            and self._DEFAULTS["choice"] in self._TYPES
        ):
            getattr(self, self._DEFAULTS["choice"])
        else:
            self._set_property("choice", choice)

    @property
    def choice(self):
        # type: () -> Union[Literal["edges"], Literal["nodes"]]
        """choice getter

        TBD

        Returns: Union[Literal["edges"], Literal["nodes"]]
        """
        return self._get_property("choice")

    @choice.setter
    def choice(self, value):
        """choice setter

        TBD

        value: Union[Literal["edges"], Literal["nodes"]]
        """
        self._set_property("choice", value)

    @property
    def nodes(self):
        # type: () -> AnnotationNodeIter
        """nodes getter

        TBD

        Returns: AnnotationNodeIter
        """
        return self._get_property(
            "nodes", AnnotationNodeIter, self._parent, self._choice
        )

    @property
    def edges(self):
        # type: () -> AnnotationEdgeIter
        """edges getter

        TBD

        Returns: AnnotationEdgeIter
        """
        return self._get_property(
            "edges", AnnotationEdgeIter, self._parent, self._choice
        )


class AnnotationNode(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "name": {"type": str},
        "attribute": {"type": str},
        "value": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, name=None, attribute=None, value=None):
        super(AnnotationNode, self).__init__()
        self._parent = parent
        self._set_property("name", name)
        self._set_property("attribute", attribute)
        self._set_property("value", value)

    def set(self, name=None, attribute=None, value=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def name(self):
        # type: () -> str
        """name getter

        A fully qualified node name that MUST exist in the graph.. server.0.npu.0. server.6.nic.3. switch.2.asic.0

        Returns: str
        """
        return self._get_property("name")

    @name.setter
    def name(self, value):
        """name setter

        A fully qualified node name that MUST exist in the graph.. server.0.npu.0. server.6.nic.3. switch.2.asic.0

        value: str
        """
        self._set_property("name", value)

    @property
    def attribute(self):
        # type: () -> str
        """attribute getter

        The attribute name that will be added to the endpoint.

        Returns: str
        """
        return self._get_property("attribute")

    @attribute.setter
    def attribute(self, value):
        """attribute setter

        The attribute name that will be added to the endpoint.

        value: str
        """
        self._set_property("attribute", value)

    @property
    def value(self):
        # type: () -> str
        """value getter

        The attribute value that will be added to the endpoint.

        Returns: str
        """
        return self._get_property("value")

    @value.setter
    def value(self, value):
        """value setter

        The attribute value that will be added to the endpoint.

        value: str
        """
        self._set_property("value", value)


class AnnotationNodeIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(AnnotationNodeIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[AnnotationNode]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> AnnotationNodeIter
        return self._iter()

    def __next__(self):
        # type: () -> AnnotationNode
        return self._next()

    def next(self):
        # type: () -> AnnotationNode
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, AnnotationNode):
            raise Exception("Item is not an instance of AnnotationNode")

    def node(self, name=None, attribute=None, value=None):
        # type: (str,str,str) -> AnnotationNodeIter
        """Factory method that creates an instance of the AnnotationNode class

        TBD

        Returns: AnnotationNodeIter
        """
        item = AnnotationNode(
            parent=self._parent, name=name, attribute=attribute, value=value
        )
        self._add(item)
        return self

    def add(self, name=None, attribute=None, value=None):
        # type: (str,str,str) -> AnnotationNode
        """Add method that creates and returns an instance of the AnnotationNode class

        TBD

        Returns: AnnotationNode
        """
        item = AnnotationNode(
            parent=self._parent, name=name, attribute=attribute, value=value
        )
        self._add(item)
        return item


class AnnotationEdge(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "ep1": {"type": str},
        "ep2": {"type": str},
        "attribute": {"type": str},
        "value": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, ep1=None, ep2=None, attribute=None, value=None):
        super(AnnotationEdge, self).__init__()
        self._parent = parent
        self._set_property("ep1", ep1)
        self._set_property("ep2", ep2)
        self._set_property("attribute", attribute)
        self._set_property("value", value)

    def set(self, ep1=None, ep2=None, attribute=None, value=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def ep1(self):
        # type: () -> str
        """ep1 getter

        A fully qualified endpoint name that MUST exist as part of an edge along with ep2 in the graph.. server.0.npu.0. server.6.nic.3. switch.2.asic.0

        Returns: str
        """
        return self._get_property("ep1")

    @ep1.setter
    def ep1(self, value):
        """ep1 setter

        A fully qualified endpoint name that MUST exist as part of an edge along with ep2 in the graph.. server.0.npu.0. server.6.nic.3. switch.2.asic.0

        value: str
        """
        self._set_property("ep1", value)

    @property
    def ep2(self):
        # type: () -> str
        """ep2 getter

        A fully qualified endpoint name that MUST exist as part of an edge along with ep1 in the graph.. server.0.npu.0. server.6.nic.3. switch.2.asic.0

        Returns: str
        """
        return self._get_property("ep2")

    @ep2.setter
    def ep2(self, value):
        """ep2 setter

        A fully qualified endpoint name that MUST exist as part of an edge along with ep1 in the graph.. server.0.npu.0. server.6.nic.3. switch.2.asic.0

        value: str
        """
        self._set_property("ep2", value)

    @property
    def attribute(self):
        # type: () -> str
        """attribute getter

        The attribute name that will be added to the edge.

        Returns: str
        """
        return self._get_property("attribute")

    @attribute.setter
    def attribute(self, value):
        """attribute setter

        The attribute name that will be added to the edge.

        value: str
        """
        self._set_property("attribute", value)

    @property
    def value(self):
        # type: () -> str
        """value getter

        The attribute value that will be added to the edge.

        Returns: str
        """
        return self._get_property("value")

    @value.setter
    def value(self, value):
        """value setter

        The attribute value that will be added to the edge.

        value: str
        """
        self._set_property("value", value)


class AnnotationEdgeIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(AnnotationEdgeIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[AnnotationEdge]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> AnnotationEdgeIter
        return self._iter()

    def __next__(self):
        # type: () -> AnnotationEdge
        return self._next()

    def next(self):
        # type: () -> AnnotationEdge
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, AnnotationEdge):
            raise Exception("Item is not an instance of AnnotationEdge")

    def edge(self, ep1=None, ep2=None, attribute=None, value=None):
        # type: (str,str,str,str) -> AnnotationEdgeIter
        """Factory method that creates an instance of the AnnotationEdge class

        TBD

        Returns: AnnotationEdgeIter
        """
        item = AnnotationEdge(
            parent=self._parent, ep1=ep1, ep2=ep2, attribute=attribute, value=value
        )
        self._add(item)
        return self

    def add(self, ep1=None, ep2=None, attribute=None, value=None):
        # type: (str,str,str,str) -> AnnotationEdge
        """Add method that creates and returns an instance of the AnnotationEdge class

        TBD

        Returns: AnnotationEdge
        """
        item = AnnotationEdge(
            parent=self._parent, ep1=ep1, ep2=ep2, attribute=attribute, value=value
        )
        self._add(item)
        return item


class Version(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "api_spec_version": {"type": str},
        "sdk_version": {"type": str},
        "app_version": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {
        "api_spec_version": "",
        "sdk_version": "",
        "app_version": "",
    }  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self, parent=None, api_spec_version="", sdk_version="", app_version=""
    ):
        super(Version, self).__init__()
        self._parent = parent
        self._set_property("api_spec_version", api_spec_version)
        self._set_property("sdk_version", sdk_version)
        self._set_property("app_version", app_version)

    def set(self, api_spec_version=None, sdk_version=None, app_version=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def api_spec_version(self):
        # type: () -> str
        """api_spec_version getter

        Version of API specification

        Returns: str
        """
        return self._get_property("api_spec_version")

    @api_spec_version.setter
    def api_spec_version(self, value):
        """api_spec_version setter

        Version of API specification

        value: str
        """
        self._set_property("api_spec_version", value)

    @property
    def sdk_version(self):
        # type: () -> str
        """sdk_version getter

        Version of SDK generated from API specification

        Returns: str
        """
        return self._get_property("sdk_version")

    @sdk_version.setter
    def sdk_version(self, value):
        """sdk_version setter

        Version of SDK generated from API specification

        value: str
        """
        self._set_property("sdk_version", value)

    @property
    def app_version(self):
        # type: () -> str
        """app_version getter

        Version of application consuming or serving the API

        Returns: str
        """
        return self._get_property("app_version")

    @app_version.setter
    def app_version(self, value):
        """app_version setter

        Version of application consuming or serving the API

        value: str
        """
        self._set_property("app_version", value)


class Api(object):
    """OpenApi Abstract API"""

    __warnings__ = []

    def __init__(self, **kwargs):
        self._version_meta = self.version()
        self._version_meta.api_spec_version = "0.5.0"
        self._version_meta.sdk_version = ""
        self._version_check = kwargs.get("version_check")
        if self._version_check is None:
            self._version_check = False
        self._version_check_err = None
        self._client_name = None
        self._client_ver = None
        self._server_name = None
        endpoint = kwargs.get("otel_collector")
        transport = kwargs.get("otel_collector_transport")
        self._telemetry = Telemetry(endpoint, transport)

    def tracer(self):
        return self._telemetry._tracer

    def add_warnings(self, msg):
        print("[WARNING]: %s" % msg, file=sys.stderr)
        self.__warnings__.append(msg)

    def _deserialize_error(self, err_string):
        # type: (str) -> Union[Error, None]
        err = self.error()
        try:
            err.deserialize(err_string)
        except Exception:
            err = None
        return err

    def from_exception(self, error):
        # type: (Exception) -> Union[Error, None]
        if isinstance(error, Error):
            return error
        elif isinstance(error, grpc.RpcError):
            err = self._deserialize_error(error.details())
            if err is not None:
                return err
            err = self.error()
            err.code = error.code().value[0]
            err.errors = [error.details()]
            return err
        elif isinstance(error, Exception):
            if len(error.args) != 1:
                return None
            if isinstance(error.args[0], Error):
                return error.args[0]
            elif isinstance(error.args[0], str):
                return self._deserialize_error(error.args[0])

    def set_graph(self, payload):
        """POST /set_graph

        Given an infrastructure object this API method will create fully qualified infrastructure graph and validate it.. Creating fully qualified infrastructure graph requires the following steps:. process each of the infrastructure instance objects by locating the device and creating subgraph using the device's edges and substituting the instance name for the device name.. process each of the infrastructure edges, looking up the instance to determine the max count and the name to be substituted for the device and link the subgraphs to create complete infrastructure graph

        Return: warning
        """
        raise NotImplementedError("set_graph")

    def get_graph(self, payload):
        """POST /get_graph

        This will return the current graph.

        Return: graphcontent
        """
        raise NotImplementedError("get_graph")

    def query_graph(self, payload):
        """POST /query_graph

        Query the current fully expanded graph using declarative query syntax.. - example: Ask the graph for specific endpoints such as those of type `NPU` or `NIC`

        Return: queryresponsecontent
        """
        raise NotImplementedError("query_graph")

    def annotate_graph(self, payload):
        """POST /annotate_graph

        Extend the current graph created by the `set_graph` API.. - example: Update specific endpoints with name/value information such as `rank=0`

        Return: warning
        """
        raise NotImplementedError("annotate_graph")

    def get_version(self):
        """GET /capabilities/version

        TBD

        Return: version
        """
        raise NotImplementedError("get_version")

    def infrastructure(self):
        """Factory method that creates an instance of Infrastructure

        Return: Infrastructure
        """
        return Infrastructure()

    def warning(self):
        """Factory method that creates an instance of Warning

        Return: Warning
        """
        return Warning()

    def error(self):
        """Factory method that creates an instance of Error

        Return: Error
        """
        return Error()

    def graphrequest(self):
        """Factory method that creates an instance of GraphRequest

        Return: GraphRequest
        """
        return GraphRequest()

    def graphcontent(self):
        """Factory method that creates an instance of GraphContent

        Return: GraphContent
        """
        return GraphContent()

    def queryrequest(self):
        """Factory method that creates an instance of QueryRequest

        Return: QueryRequest
        """
        return QueryRequest()

    def queryresponsecontent(self):
        """Factory method that creates an instance of QueryResponseContent

        Return: QueryResponseContent
        """
        return QueryResponseContent()

    def annotaterequest(self):
        """Factory method that creates an instance of AnnotateRequest

        Return: AnnotateRequest
        """
        return AnnotateRequest()

    def version(self):
        """Factory method that creates an instance of Version

        Return: Version
        """
        return Version()

    def close(self):
        pass

    def set_component_info(self, client_name, client_version, server_name):
        self._client_name = client_name
        self._client_app_ver = client_version
        self._server_name = server_name

    def _check_client_server_version_compatibility(
        self, client_ver, server_ver, component_name
    ):
        try:
            c = semantic_version.Version(client_ver)
        except Exception as e:
            raise AssertionError(
                "Client {} version '{}' is not a valid semver: {}".format(
                    component_name, client_ver, e
                )
            )

        try:
            s = semantic_version.SimpleSpec(server_ver)
        except Exception as e:
            raise AssertionError(
                "Server {} version '{}' is not a valid semver: {}".format(
                    component_name, server_ver, e
                )
            )

        err = "Client {} version '{}' is not semver compatible with Server {} version '{}'".format(
            component_name, client_ver, component_name, server_ver
        )

        if not s.match(c):
            raise Exception(err)

    def get_local_version(self):
        log.info("Local Version is " + str(self._version_meta))
        return self._version_meta

    def get_remote_version(self):
        log.info("Remote Version is " + str(self.get_version()))
        return self.get_version()

    def check_version_compatibility(self):
        comp_err, api_err = self._do_version_check()
        if comp_err is not None:
            raise comp_err
        if api_err is not None:
            raise api_err

    def _do_version_check(self):
        local = self.get_local_version()
        try:
            remote = self.get_remote_version()
        except Exception as e:
            return None, e

        try:
            self._check_client_server_version_compatibility(
                local.api_spec_version, remote.api_spec_version, "API spec"
            )
        except Exception as e:
            if self._client_name is not None:
                msg = "{} {} is not compatible with {} {}".format(
                    self._client_name,
                    self._client_app_ver,
                    self._server_name,
                    remote.app_version,
                )
                return Exception(msg), None
            else:
                msg = "client SDK version '{}' is not compatible with server SDK version '{}'".format(
                    local.sdk_version, remote.sdk_version
                )
                return Exception("{}: {}".format(msg, str(e))), None

        return None, None

    def _do_version_check_once(self):
        if not self._version_check:
            return

        if self._version_check_err is not None:
            raise self._version_check_err

        comp_err, api_err = self._do_version_check()
        if comp_err is not None:
            self._version_check_err = comp_err
            raise comp_err
        if api_err is not None:
            self._version_check_err = None
            raise api_err

        self._version_check = False
        self._version_check_err = None


class HttpApi(Api):
    """OpenAPI HTTP Api"""

    def __init__(self, **kwargs):
        super(HttpApi, self).__init__(**kwargs)
        self._transport = HttpTransport(**kwargs)
        self._telemetry.initiate_http_instrumentation()

    @property
    def verify(self):
        return self._transport.verify

    @verify.setter
    def verify(self, value):
        self._transport.set_verify(value)

    @Telemetry.create_child_span
    def set_graph(self, payload):
        """POST /set_graph

        Given an infrastructure object this API method will create fully qualified infrastructure graph and validate it.. Creating fully qualified infrastructure graph requires the following steps:. process each of the infrastructure instance objects by locating the device and creating subgraph using the device's edges and substituting the instance name for the device name.. process each of the infrastructure edges, looking up the instance to determine the max count and the name to be substituted for the device and link the subgraphs to create complete infrastructure graph

        Return: warning
        """
        log.info("Executing set_graph")
        self._do_version_check_once()
        return self._transport.send_recv(
            "post",
            "/set_graph",
            payload=payload,
            return_object=self.warning(),
            request_class=Infrastructure,
        )

    @Telemetry.create_child_span
    def get_graph(self, payload):
        """POST /get_graph

        This will return the current graph.

        Return: graphcontent
        """
        log.info("Executing get_graph")
        self._do_version_check_once()
        return self._transport.send_recv(
            "post",
            "/get_graph",
            payload=payload,
            return_object=self.graphcontent(),
            request_class=GraphRequest,
        )

    @Telemetry.create_child_span
    def query_graph(self, payload):
        """POST /query_graph

        Query the current fully expanded graph using declarative query syntax.. - example: Ask the graph for specific endpoints such as those of type `NPU` or `NIC`

        Return: queryresponsecontent
        """
        log.info("Executing query_graph")
        self._do_version_check_once()
        return self._transport.send_recv(
            "post",
            "/query_graph",
            payload=payload,
            return_object=self.queryresponsecontent(),
            request_class=QueryRequest,
        )

    @Telemetry.create_child_span
    def annotate_graph(self, payload):
        """POST /annotate_graph

        Extend the current graph created by the `set_graph` API.. - example: Update specific endpoints with name/value information such as `rank=0`

        Return: warning
        """
        log.info("Executing annotate_graph")
        self._do_version_check_once()
        return self._transport.send_recv(
            "post",
            "/annotate_graph",
            payload=payload,
            return_object=self.warning(),
            request_class=AnnotateRequest,
        )

    @Telemetry.create_child_span
    def get_version(self):
        """GET /capabilities/version

        TBD

        Return: version
        """
        log.info("Executing get_version")
        return self._transport.send_recv(
            "get",
            "/capabilities/version",
            payload=None,
            return_object=self.version(),
        )


class GrpcApi(Api):
    # OpenAPI gRPC Api
    def __init__(self, **kwargs):
        super(GrpcApi, self).__init__(**kwargs)
        self._stub = None
        self._channel = None
        self._cert = None
        self._cert_domain = None
        self._request_timeout = 10
        self._keep_alive_timeout = 10 * 1000
        self._maximum_receive_buffer_size = 4 * 1024 * 1024
        self.enable_grpc_streaming = False
        self._chunk_size = 4 * 1024 * 1024
        self._location = (
            kwargs["location"]
            if "location" in kwargs and kwargs["location"] is not None
            else "localhost:50051"
        )
        self._transport = kwargs["transport"] if "transport" in kwargs else None
        log.debug(
            "gRPCTransport args: {}".format(
                ", ".join(["{}={!r}".format(k, v) for k, v in kwargs.items()])
            )
        )
        self._telemetry.initiate_grpc_instrumentation()

    def _use_secure_connection(self, cert_path, cert_domain=None):
        """Accepts certificate and host_name for SSL Connection."""
        if cert_path is None:
            raise Exception("path to certificate cannot be None")
        self._cert = cert_path
        self._cert_domain = cert_domain

    def _get_stub(self):
        if self._stub is None:
            CHANNEL_OPTIONS = [
                ("grpc.enable_retries", 0),
                ("grpc.keepalive_timeout_ms", self._keep_alive_timeout),
                ("grpc.max_receive_message_length", self._maximum_receive_buffer_size),
            ]
            if self._cert is None:
                self._channel = grpc.insecure_channel(
                    self._location, options=CHANNEL_OPTIONS
                )
            else:
                crt = open(self._cert, "rb").read()
                creds = grpc.ssl_channel_credentials(crt)
                if self._cert_domain is not None:
                    CHANNEL_OPTIONS.append(
                        ("grpc.ssl_target_name_override", self._cert_domain)
                    )
                self._channel = grpc.secure_channel(
                    self._location, credentials=creds, options=CHANNEL_OPTIONS
                )
            self._stub = pb2_grpc.OpenapiStub(self._channel)
        return self._stub

    def _serialize_payload(self, payload):
        if not isinstance(payload, (str, dict, OpenApiBase)):
            raise Exception("We are supporting [str, dict, OpenApiBase] object")
        if isinstance(payload, OpenApiBase):
            payload = payload.serialize()
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        elif isinstance(payload, (str, unicode)):
            payload = json.dumps(yaml.safe_load(payload))
        return payload

    def _raise_exception(self, grpc_error):
        err = self.error()
        try:
            err.deserialize(grpc_error.details())
        except Exception as _:
            err.code = grpc_error.code().value[0]
            err.errors = [grpc_error.details()]
        raise Exception(err)

    def _client_stream(self, stub, data):
        data_chunks = []
        for i in range(0, len(data), self._chunk_size):
            if i + self._chunk_size > len(data):
                chunk = data[i : len(data)]
            else:
                chunk = data[i : i + self._chunk_size]
            data_chunks.append(pb2.Data(datum=chunk, chunk_size=self._chunk_size))
        # print(chunk_list, len(chunk_list))
        reqs = iter(data_chunks)
        return reqs

    def _server_stream(self, stub, responses):
        data = b""
        for response in responses:
            data += response.datum
        return data

    @property
    def request_timeout(self):
        """duration of time in seconds to allow for the RPC."""
        return self._request_timeout

    @request_timeout.setter
    def request_timeout(self, timeout):
        self._request_timeout = timeout

    @property
    def keep_alive_timeout(self):
        return self._keep_alive_timeout

    @keep_alive_timeout.setter
    def keep_alive_timeout(self, timeout):
        self._keep_alive_timeout = timeout * 1000

    @property
    def chunk_size(self):
        return self._chunk_size

    @chunk_size.setter
    def chunk_size(self, size):
        self._chunk_size = size * 1024 * 1024

    @property
    def maximum_receive_buffer_size(self):
        return self._maximum_receive_buffer_size

    @maximum_receive_buffer_size.setter
    def maximum_receive_buffer_size(self, size):
        self._maximum_receive_buffer_size = size * 1024 * 1024

    def close(self):
        if self._channel is not None:
            self._channel.close()
            self._channel = None
            self._stub = None

    @Telemetry.create_child_span
    def set_graph(self, payload):
        log.info("Executing set_graph")
        log.debug("Request payload - " + str(payload))
        self._telemetry.set_span_event("REQUEST: %s" % str(payload))
        pb_obj = json_format.Parse(
            self._serialize_payload(payload), pb2.Infrastructure()
        )
        self._do_version_check_once()
        req_obj = pb2.SetGraphRequest(infrastructure=pb_obj)
        pb_str = pb_obj.SerializeToString()
        stub = self._get_stub()
        try:
            if self.enable_grpc_streaming and len(pb_str) > self._chunk_size:
                stream_req = self._client_stream(stub, pb_str)
                res_obj = stub.streamSetGraph(stream_req, timeout=self._request_timeout)
            else:
                res_obj = stub.SetGraph(req_obj, timeout=self._request_timeout)
        except grpc.RpcError as grpc_error:
            self._raise_exception(grpc_error)
        response = json_format.MessageToDict(res_obj, preserving_proto_field_name=True)
        log.debug("Response - " + str(response))
        self._telemetry.set_span_event("RESPONSE: %s" % str(response))
        result = response.get("warning")
        if result is not None:
            if len(result) == 0:
                result = json_format.MessageToDict(
                    res_obj.warning,
                    preserving_proto_field_name=True,
                    always_print_fields_with_no_presence=True,
                )
            return self.warning().deserialize(result)

    @Telemetry.create_child_span
    def get_graph(self, payload):
        log.info("Executing get_graph")
        log.debug("Request payload - " + str(payload))
        self._telemetry.set_span_event("REQUEST: %s" % str(payload))
        pb_obj = json_format.Parse(self._serialize_payload(payload), pb2.GraphRequest())
        self._do_version_check_once()
        req_obj = pb2.GetGraphRequest(graphrequest=pb_obj)
        pb_str = pb_obj.SerializeToString()
        stub = self._get_stub()
        try:
            if self.enable_grpc_streaming and len(pb_str) > self._chunk_size:
                stream_req = self._client_stream(stub, pb_str)
                res_obj = stub.streamGetGraph(stream_req, timeout=self._request_timeout)
            else:
                res_obj = stub.GetGraph(req_obj, timeout=self._request_timeout)
        except grpc.RpcError as grpc_error:
            self._raise_exception(grpc_error)
        response = json_format.MessageToDict(res_obj, preserving_proto_field_name=True)
        log.debug("Response - " + str(response))
        self._telemetry.set_span_event("RESPONSE: %s" % str(response))
        result = response.get("graph_content")
        if result is not None:
            return self.graphcontent().deserialize(result)

    @Telemetry.create_child_span
    def query_graph(self, payload):
        log.info("Executing query_graph")
        log.debug("Request payload - " + str(payload))
        self._telemetry.set_span_event("REQUEST: %s" % str(payload))
        pb_obj = json_format.Parse(self._serialize_payload(payload), pb2.QueryRequest())
        self._do_version_check_once()
        req_obj = pb2.QueryGraphRequest(queryrequest=pb_obj)
        pb_str = pb_obj.SerializeToString()
        stub = self._get_stub()
        try:
            if self.enable_grpc_streaming and len(pb_str) > self._chunk_size:
                stream_req = self._client_stream(stub, pb_str)
                res_obj = stub.streamQueryGraph(
                    stream_req, timeout=self._request_timeout
                )
            else:
                res_obj = stub.QueryGraph(req_obj, timeout=self._request_timeout)
        except grpc.RpcError as grpc_error:
            self._raise_exception(grpc_error)
        response = json_format.MessageToDict(res_obj, preserving_proto_field_name=True)
        log.debug("Response - " + str(response))
        self._telemetry.set_span_event("RESPONSE: %s" % str(response))
        result = response.get("query_response_content")
        if result is not None:
            return self.queryresponsecontent().deserialize(result)

    @Telemetry.create_child_span
    def annotate_graph(self, payload):
        log.info("Executing annotate_graph")
        log.debug("Request payload - " + str(payload))
        self._telemetry.set_span_event("REQUEST: %s" % str(payload))
        pb_obj = json_format.Parse(
            self._serialize_payload(payload), pb2.AnnotateRequest()
        )
        self._do_version_check_once()
        req_obj = pb2.AnnotateGraphRequest(annotaterequest=pb_obj)
        pb_str = pb_obj.SerializeToString()
        stub = self._get_stub()
        try:
            if self.enable_grpc_streaming and len(pb_str) > self._chunk_size:
                stream_req = self._client_stream(stub, pb_str)
                res_obj = stub.streamAnnotateGraph(
                    stream_req, timeout=self._request_timeout
                )
            else:
                res_obj = stub.AnnotateGraph(req_obj, timeout=self._request_timeout)
        except grpc.RpcError as grpc_error:
            self._raise_exception(grpc_error)
        response = json_format.MessageToDict(res_obj, preserving_proto_field_name=True)
        log.debug("Response - " + str(response))
        self._telemetry.set_span_event("RESPONSE: %s" % str(response))
        result = response.get("warning")
        if result is not None:
            if len(result) == 0:
                result = json_format.MessageToDict(
                    res_obj.warning,
                    preserving_proto_field_name=True,
                    always_print_fields_with_no_presence=True,
                )
            return self.warning().deserialize(result)

    @Telemetry.create_child_span
    def get_version(self):
        log.info("Executing get_version")
        stub = self._get_stub()
        empty = pb2_grpc.google_dot_protobuf_dot_empty__pb2.Empty()
        res_obj = stub.GetVersion(empty, timeout=self._request_timeout)
        response = json_format.MessageToDict(res_obj, preserving_proto_field_name=True)
        log.debug("Response - " + str(response))
        self._telemetry.set_span_event("RESPONSE: %s" % str(response))
        result = response.get("version")
        if result is not None:
            return self.version().deserialize(result)
