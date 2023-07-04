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

import argparse

from uosrzidmgr.config import update_configuration, config


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='UOS LDAP account manager for IT admins',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '-c', '--config',
        type=str,
        default=None,
        help='Path to a configuration file'
    )
    parser.add_argument(
        '-d', '--debug',
        default=False,
        action='store_true',
        help='Start web server in debug mode'
    )
    args = parser.parse_args()
    if args.config:
        update_configuration(args.config)

    # Since `app` will use the configuration,
    # load it only after we updated the configuration location
    from uosrzidmgr.web import app

    app.run(debug=args.debug)
