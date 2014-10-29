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

"""Authentication Library"""

import argparse
import getpass
import logging
import sys
import time

from keystoneclient import auth
from keystoneclient.auth.identity import generic
from keystoneclient.auth.identity import v2
from keystoneclient.auth.identity import v3
from keystoneclient.auth import token_endpoint
from keystoneclient import session
from oslo.config import cfg

from openstackclient.common import exceptions as exc
from openstackclient.common import utils

LOG = logging.getLogger(__name__)


class Session(session.Session):

    def __init__(self, *args, **kwargs):
        self._record_timings = kwargs.pop('timing', False)
        self.timing_data = []
        super(Session, self).__init__(*args, **kwargs)

    def request(self, path, method, **kwargs):
        if self._record_timings:
            start = time.time()

        resp = super(Session, self).request(path, method, **kwargs)

        if self._record_timings:
            self.timing_data.append(("%s %s" % (method, resp.url),
                                     start,
                                     time.time()))

        return resp

    @classmethod
    def register_cli_options(cls, parser):
        super(Session, cls).register_cli_options(parser)

        parser.add_argument('--timing',
                            default=False,
                            action='store_true',
                            help="Print API call timing info")

    @classmethod
    def load_from_cli_options(cls, args, **kwargs):
        kwargs['timing'] = args.timing
        return super(Session, cls).load_from_cli_options(args, **kwargs)


class OSCDefaultAuthPlugin(auth.BaseAuthPlugin):

    def __init__(self, plugin):
        self._plugin = plugin

    # PROXY FUNCTIONS - emulate a real plugin and send to the inner one.
    def get_endpoint(self, *args, **kwargs):
        return self._plugin.get_endpoint(*args, **kwargs)

    def get_token(self, *args, **kwargs):
        return self._plugin.get_token(*args, **kwargs)

    def invalidate(self, *args, **kwargs):
        return self._plugin.invalidate(*args, **kwargs)

    @classmethod
    def get_options(cls):
        options = super(OSCDefaultAuthPlugin, cls).get_options()

        options.extend([
            cfg.StrOpt('auth-url',
                       help='Authentication URL (Env: OS_AUTH_URL)'),

            cfg.StrOpt('username',
                       help='Authentication username (Env: OS_USERNAME)'),
            cfg.StrOpt('password',
                       help='Authentication password (Env: OS_PASSWORD)'),

            cfg.StrOpt('user-domain-id',
                       help='Domain ID of the user (Env: OS_USER_DOMAIN_ID)'),
            cfg.StrOpt('user-domain-name',
                       help='Domain name of the user '
                            '(Env: OS_USER_DOMAIN_NAME)'),

            cfg.StrOpt('project-id',
                       help='Project ID of the requested project-level '
                            'authorization scope (Env: OS_PROJECT_ID)'),
            cfg.StrOpt('project-name',
                       help='Project name of the requested project-level '
                            'authorization scope (Env: OS_PROJECT_NAME)'),

            cfg.StrOpt('project-domain-id',
                       help='Domain ID of the project which is the requested '
                            'project-level authorization scope '
                            '(Env: OS_PROJECT_DOMAIN_ID)'),
            cfg.StrOpt('project-domain-name',
                       help='Domain name of the project which is the requested'
                            ' project-level authorization scope'
                            ' (Env: OS_PROJECT_DOMAIN_NAME)'),

            cfg.StrOpt('domain-id',
                       help='Domain ID of the requested domain-level '
                            'authorization scope (Env: OS_DOMAIN_ID)'),
            cfg.StrOpt('domain-name',
                       help='Domain name of the requested domain-level '
                            'authorization scope (Env: OS_DOMAIN_NAME)'),

            # Maintain name 'url' for compatibility
            cfg.StrOpt('url',
                       help='Specific service endpoint to use'),
            cfg.StrOpt('token',
                       secret=True,
                       help='Authentication token to use'),
        ])

        return options

    @classmethod
    def register_argparse_arguments(cls, parser):
        super(OSCDefaultAuthPlugin, cls).register_argparse_arguments(parser)

        parser.add_argument('--os-tenant-id',
                            metavar='<auth-tenant-id>',
                            dest='os_project_id',
                            default=utils.env('OS_TENANT_ID'),
                            help=argparse.SUPPRESS)
        parser.add_argument('--os-tenant-name',
                            metavar='<auth-tenant-name>',
                            dest='os_project_name',
                            default=utils.env('OS_TENANT_NAME'),
                            help=argparse.SUPPRESS)

    @classmethod
    def load_from_argparse_arguments(cls, namespace, **kwargs):
        kwargs['identity_api_version'] = namespace.os_identity_api_version
        return super(OSCDefaultAuthPlugin, cls).load_from_argparse_arguments(
            namespace, **kwargs)

    @classmethod
    def load_from_options(cls, url=None, token=None, username=None,
                          password=None, project_id=None, project_name=None,
                          domain_id=None, domain_name=None, trust_id=None,
                          auth_url=None, identity_api_version=None,
                          user_domain_id=None, user_domain_name=None,
                          project_domain_id=None, project_domain_name=None,
                          **kwargs):
        plugin = None

        if url or token:
            # Token flow auth takes priority
            if not token:
                raise exc.CommandError(
                    "You must provide a token via"
                    " either --os-token or env[OS_TOKEN]")

            if not url:
                raise exc.CommandError(
                    "You must provide a service URL via"
                    " either --os-url or env[OS_URL]")

            plugin = token_endpoint.Token(url, token)

        else:
            if not username:
                raise exc.CommandError(
                    "You must provide a username via"
                    " either --os-username or env[OS_USERNAME]")

            if not password:
                # No password, if we've got a tty, try prompting for it
                if hasattr(sys.stdin, 'isatty') and sys.stdin.isatty():
                    # Check for Ctl-D
                    try:
                        password = getpass.getpass('Password: ')
                    except EOFError:
                        pass

            # No password because we did't have a tty or the
            # user Ctl-D when prompted?
            if not password:
                raise exc.CommandError(
                    "You must provide a password via"
                    " either --os-password, or env[OS_PASSWORD], "
                    " or prompted response")

            mutual_exclusion_count = sum((bool(project_id or project_name),
                                          bool(domain_id or domain_name),
                                          bool(trust_id)))

            if not auth_url:
                raise exc.CommandError(
                    "You must provide an auth url via"
                    " either --os-auth-url or via env[OS_AUTH_URL]")

            if mutual_exclusion_count == 0:
                raise exc.CommandError(
                    "You must provide authentication scope as a project "
                    "or a domain via --os-project-id or env[OS_PROJECT_ID]"
                    " --os-project-name or env[OS_PROJECT_NAME],"
                    " --os-domain-id or env[OS_DOMAIN_ID], or"
                    " --os-domain-name or env[OS_DOMAIN_NAME], or"
                    " --os-trust-id or env[OS_TRUST_ID].")
            elif mutual_exclusion_count > 1:
                raise exc.CommandError(
                    "Authentication cannot be scoped to multiple targets. "
                    "Pick one of project, domain or trust.")

            if trust_id and identity_api_version != '3':
                raise exc.CommandError(
                    "Trusts can only be used with Identity API v3")

            if identity_api_version == '3':
                plugin = v3.Password(auth_url=auth_url,
                                     username=username,
                                     password=password,
                                     user_domain_id=user_domain_id,
                                     user_domain_name=user_domain_name,
                                     trust_id=trust_id,
                                     domain_id=domain_id,
                                     domain_name=domain_name,
                                     project_id=project_id,
                                     project_name=project_name,
                                     project_domain_id=project_domain_id,
                                     project_domain_name=project_domain_name)

            elif identity_api_version == '2.0':
                plugin = v2.Password(auth_url=auth_url,
                                     username=username,
                                     password=password,
                                     tenant_id=project_id,
                                     tenant_name=project_name)

            elif not identity_api_version:
                plugin = generic.Password(
                    auth_url=auth_url,
                    username=username,
                    password=password,
                    user_domain_id=user_domain_id,
                    user_domain_name=user_domain_name,
                    trust_id=trust_id,
                    domain_id=domain_id,
                    domain_name=domain_name,
                    project_id=project_id,
                    project_name=project_name,
                    project_domain_id=project_domain_id,
                    project_domain_name=project_domain_name)

            else:
                raise exc.CommandError(
                    "Invalid identity_api_version specified. "
                    "Must be '2.0' or '3'"
                )

        return cls(plugin)
