# LDAP user registration form
# Copyright 2023 Osnabrück University
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import logging
import os
import yaml

# Logger
logger = logging.getLogger(__name__)

__config = {}


def configuration_file():
    '''Find the best match for the configuration file.  The configuration file
    locations taken into consideration are (in this particular order):

    - ``./rz-id-manager.yml``
    - ``~/rz-id-manager.yml``
    - ``/etc/rz-id-manager.yml``

    :return: configuration file name or None
    '''
    if os.path.isfile('./rz-id-manager.yml'):
        return './rz-id-manager.yml'
    expanded_file = os.path.expanduser('~/rz-id-manager.yml')
    if os.path.isfile(expanded_file):
        return expanded_file
    if os.path.isfile('/etc/rz-id-manager.yml'):
        return '/etc/rz-id-manager.yml'


def update_configuration(filename=None):
    '''Update configuration.
    '''
    cfgfile = filename or configuration_file()
    if not cfgfile:
        return {}
    print(f'Loading configuration from {cfgfile}')
    with open(cfgfile, 'r') as f:
        cfg = yaml.safe_load(f)
    globals()['__config'] = cfg

    # update logger
    loglevel = cfg.get('loglevel', 'INFO').upper()
    logging.root.setLevel(loglevel)
    logger.info('Log level set to %s', loglevel)

    return cfg


def config(*args, allow_empty=True):
    '''Get a specific configuration value or the whole configuration, loading
    the configuration file if it was not before.

    :param key: optional configuration key to return
    :type key: string
    :return: dictionary containing the configuration or configuration value
    '''
    cfg = __config or update_configuration()
    for key in args:
        if cfg is None:
            if allow_empty:
                return
            raise KeyError(f'Missing configuration key {args}')
        cfg = cfg.get(key)
    return cfg
