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

#
"""
Ezbake Configuration for Python

Reads configuration from package data in config/ezbake-config.properties

Modules that import any of the ezconfig modules can override properties by
including their own config/ezbake-config.properties

ex)
    mypackage/
        -mymodule.py
        -config/
            -ezbake-config.properties

    mymodule.py:
    import ezconfig.zookeeper

NOTE: the configuration properties are loaded when ezconfig._config is imported
    (by any of the helper modules), so only the first module's
    config/ezbake-config.properties can be used
"""
# this is a namespace package
try:
    import pkg_resources
    pkg_resources.declare_namespace(__name__)
except ImportError:
    import pkgutil
    __path__ = pkgutil.extend_path(__path__, __name__)
