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

from functools import wraps
import logging
import enum

import sqlalchemy
from sqlalchemy import create_engine, Column, Date, DateTime, String, Enum, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from uosrzidmgr.config import config

# Logger
logger = logging.getLogger(__name__)

# Database uri as described in
# https://docs.sqlalchemy.org/en/13/core/engines.html#database-urls
# Retrieved as environment variable.
database = config('database') or 'sqlite:///rz-id-manager.db'

# Global session variable. Set on initialization.
__session__ = None

# Base Class of all ORM objects.
Base = declarative_base()


class Status(enum.Enum):
    created = 1
    invited = 2
    timeout = 3
    cancelled = 4

class Gender(enum.Enum):
    male = 1
    female = 2
    diverse = 3


class AccountType(enum.Enum):
    staff = 1
    guest = 2
    service = 3


class Account(Base):
    """ORM object for accounts.
    """
    __tablename__ = 'account'
    login = Column(String, primary_key=True)
    '''LDAP login'''
    requested = Column(DateTime, nullable=False)
    created = Column(DateTime)
    status = Column(Enum(Status))
    account_type = Column(Enum(AccountType))
    management_login = Column(String)
    gender = Column(Enum(Gender))
    name_given = Column(String)
    name_family = Column(String)
    title = Column(String)
    birthday = Column(Date)
    organizational_unit = Column(String)
    work_street = Column(String)
    work_street_no = Column(String)
    work_post_code = Column(Integer)
    work_city = Column(String)
    work_phone = Column(String)
    private_street = Column(String)
    private_street_no = Column(String)
    private_post_code = Column(Integer)
    private_city = Column(String)
    private_email = Column(String)
    private_phone = Column(String)
    invitation_key = Column(String)



def with_session(f):
    """Wrapper for f to make a SQLAlchemy session present within the function

    :param f: Function to call
    :type f: Function
    :raises e: Possible exception of f
    :return: Result of f
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Get new session
        session = get_session()
        try:
            # Call f with the session and all the other arguments
            result = f(session, *args, **kwargs)
        except Exception as e:
            # Rollback session, something bad happend.
            session.rollback()
            session.close()
            raise e
        # Close session and return the result of f
        session.close()
        return result
    return decorated


def get_session():
    """Get a new session.

    Lazy load the database connection and create the tables.

    Returns:
        sqlalchemy.orm.session.Session -- SQLAlchemy Session object
    """
    global __session__
    # Create database connection, tables and Sessionmaker if neccessary.
    if not __session__:
        Engine = create_engine(
            database, echo=logger.getEffectiveLevel() == logging.DEBUG)
        __session__ = sessionmaker(bind=Engine)
        Base.metadata.create_all(Engine)

    # Return new session object
    return __session__()
