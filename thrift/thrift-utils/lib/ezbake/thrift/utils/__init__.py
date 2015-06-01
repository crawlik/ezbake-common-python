#   Copyright (C) 2013-2014 Computer Sciences Corporation
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import base64
from thrift import TSerialization

def serialize_to_base64(thrift_object):
    """
    Serializes the given Thrift object, and encodes it in base64.

    :param thrift_object: A thrift object that you want to serialize and encode.
    :return: Base64-Encoded and Serialzed Thrift object
    """
    serialized_object = TSerialization.serialize(thrift_object)
    return base64.b64encode(serialized_object)


def deserialize_from_base64(base, base64_encoded_string):
    """
    Deserializes the given Thrift object from base64 encoded string

    :param base: thrift object class to be deserialized into
    :param base64_encoded_string: A base64 encoded string of the serialized bytes of a thrift object
    :return: the decoded thrift object
    """
    serialized_object = base64.b64decode(base64_encoded_string)
    return TSerialization.deserialize(base(), serialized_object)
