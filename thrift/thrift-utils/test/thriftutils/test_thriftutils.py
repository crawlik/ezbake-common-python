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

import nose.tools as nt

from ..ezpz.t import ttypes
from ezbake.thrift import utils


class TestThriftUtils(object):

    def test_serialize_deserialize(self):
        original_object = ttypes.Test(15, "testobject")

        # test serialization, not sure how to make sure it's base64
        base64_serialized = utils.serialize_to_base64(original_object)
        nt.assert_is_instance(base64_serialized, str)

        # test deserialization, make sure we get back the type we're expecting
        deserialized_object = utils.deserialize_from_base64(ttypes.Test, base64_serialized)
        nt.assert_is_instance(deserialized_object, ttypes.Test)

        # make sure the deserialized object equals the original
        nt.assert_equal(original_object, deserialized_object)
