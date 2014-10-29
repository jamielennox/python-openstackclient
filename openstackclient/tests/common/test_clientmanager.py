#   Copyright 2012-2013 OpenStack Foundation
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
#

from keystoneclient.auth.identity import v2 as auth_v2

from openstackclient.common import clientmanager
from openstackclient.tests import fakes
from openstackclient.tests import utils

AUTH_REF = {'a': 1}
AUTH_TOKEN = "foobar"
SERVICE_CATALOG = {'sc': '123'}
API_VERSION = {'identity': '2.0'}


def FakeMakeClient(instance):
    return FakeClient()


class FakeClient(object):
    auth_ref = AUTH_REF
    auth_token = AUTH_TOKEN
    service_catalog = SERVICE_CATALOG


class Container(object):
    attr = clientmanager.ClientCache(lambda x: object())

    def __init__(self):
        pass


class FakeOptions(object):
    def __init__(self, **kwargs):
        self.os_auth_plugin = None
        self.os_identity_api_version = '2.0'
        self.timing = None
        self.os_region_name = None
        self.os_url = None
        self.insecure = False
        self.os_cacert = None
        self.os_cert = None
        self.os_key = None
        self.timeout = None
        self.__dict__.update(kwargs)


class TestClientCache(utils.TestCase):

    def test_singleton(self):
        # NOTE(dtroyer): Verify that the ClientCache descriptor only invokes
        # the factory one time and always returns the same value after that.
        c = Container()
        self.assertEqual(c.attr, c.attr)


class TestClientManager(utils.TestCase):
    def setUp(self):
        super(TestClientManager, self).setUp()

        clientmanager.ClientManager.identity = \
            clientmanager.ClientCache(FakeMakeClient)


    def test_client_manager_password(self):

        client_manager = clientmanager.ClientManager(
            auth_options=FakeOptions(os_auth_url=fakes.AUTH_URL,
                                     os_username=fakes.USERNAME,
                                     os_password=fakes.PASSWORD),
            api_version=API_VERSION,
        )
        self.assertEqual(client_manager._api_version, API_VERSION)
        self.assertIsNone(client_manager._region_name)
