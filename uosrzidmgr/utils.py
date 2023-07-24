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

import random
import string

from uosrzidmgr.config import config


def random_string(length):
    '''Generate a random string with gicen length.
    '''
    return ''.join(random.choices(string.ascii_letters, k=length))


def organizational_unit(admin):
    '''Get organizational unit for a given admin from the configuration.
    '''
    for ou, admins in config('admins').items():
        if admin in admins:
            return ou
    return None
