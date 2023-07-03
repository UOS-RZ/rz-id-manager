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

import glob
import logging
import os
import yaml

from datetime import datetime
from dateutil.parser import parse
from flask import Flask, request, redirect, render_template, session, jsonify
from functools import wraps
from ldap3.core.exceptions import LDAPBindError, LDAPPasswordIsMandatoryError

from uosrzidmgr.config import config
from uosrzidmgr.ldap import ldap_login, check_login
from uosrzidmgr.db import with_session, Account, Status, AccountType

# Logger
logger = logging.getLogger(__name__)

flask_config = {}
if config('ui', 'directories', 'template'):
    flask_config['template_folder'] = config('ui', 'directories', 'template')
if config('ui', 'directories', 'static'):
    flask_config['static_folder'] = config('ui', 'directories', 'static')
app = Flask(__name__, **flask_config)
app.secret_key = 'CHANHE_ME'

__error = {}
__i18n = {}
__languages = []


def organizational_unit(admin):
    for ou, admins in config('admins').items():
        if admin in admins:
            return ou
    return None


def error(error_id: str, code: int) -> tuple[str, int]:
    '''Generate error page based on data defined in `error.yml` and the given
    error identifier.

    :param error_id: String identifying the error to render.
    :param code: HTTP status code to return.
    :returns: Tuple of data for Flask response
    '''
    lang = request.accept_languages.best_match(__languages)
    logger.debug('Using language: %s', lang)
    error_data = __error[lang][error_id].copy()
    error_data['i18n'] = __i18n[lang]
    return render_template('error.html', **error_data), code


def handle_errors(function):
    '''Decorator handling common errors.
    This will cause an errpr page to be rendered.

    :param function: Function to wrap.
    '''
    @wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (LDAPBindError, LDAPPasswordIsMandatoryError) as e:
            logger.info('LDAP login failed: %s', e)
            return error('invalid_credentials', 403)
        except KeyError as e:
            logger.info('Only verified IT admins are allowed to log-in: %s', e)
            return error('non_it_admin', 401)
    return wrapper


def init():
    '''Load internationalization and try to register the authentication system.
    '''
    # load internationalization data
    files = glob.glob(os.path.dirname(__file__) + '/i18n/error-*.yml')
    globals()['__languages'] = {os.path.basename(f)[6:-4] for f in files}
    logger.info('Detected available languages: %s', __languages)

    for lang in __languages:
        # load error messages
        i18n_file = os.path.dirname(__file__) + f'/i18n/error-{lang}.yml'
        with open(i18n_file, 'r') as f:
            globals()['__error'][lang] = yaml.safe_load(f)

        # load internationalization file
        i18n_file = os.path.dirname(__file__) + f'/i18n/i18n-{lang}.yml'
        with open(i18n_file, 'r') as f:
            globals()['__i18n'][lang] = yaml.safe_load(f)


@app.errorhandler(500)
def internal_server_error(e):
    '''Handle internal server errors.
    This causes the app to render an error page similar to known and caught
    errors.
    '''
    return error('internal', 500)


def verify_login(function):
    '''Decorator ensuring users are logged in.
    It provides data about the logged in user to wrapped funstions.

    :param function: Function to wrap.
    '''
    @wraps(function)
    def wrapper(*args, **kwargs):
        i18n = __i18n[request.accept_languages.best_match(__languages) or 'en']
        user, email, given, family = session.get('login') or ([None] * 4)
        if not user:
            return render_template('login.html', i18n=i18n)

        ou = organizational_unit(user)

        data = {'i18n': i18n,
                'organizational_unit': ou,
                'user': user,
                'email': email,
                'given': given,
                'family': family}
        return function(*args, user_data=data, **kwargs)
    return wrapper


@app.route('/', methods=['GET'])
@handle_errors
@verify_login
@with_session
def home(db, user_data):
    users = db.query(Account)
    return render_template('index.html', users=users, **user_data)


@app.route('/', methods=['POST'])
@handle_errors
def login():
    # get form data
    user = request.form.get('user')
    password = request.form.get('password')

    if not organizational_unit(user):
        raise KeyError(f'User "{user}" not found in list of admins')

    # Login to and get user data from LDAP
    user_data = ldap_login(user, password)

    email = user_data[config('ldap', 'userdata', 'email')][0]
    given = user_data[config('ldap', 'userdata', 'name', 'given')]
    family = user_data[config('ldap', 'userdata', 'name', 'family')]
    session['login'] = (user, email, given, family)

    return redirect('/', code=302)


@app.route('/service_account', methods=['GET'])
@handle_errors
@verify_login
def service_account_form(user_data):
    return render_template('create_service_account.html', **user_data)


@app.route('/service_account', methods=['POST'])
@with_session
@verify_login
@handle_errors
def service_account_create(db, user_data):
    now = datetime.now()

    account = Account()
    account.login = request.form.get('login')
    account.password = request.form.get('password')
    account.organizational_unit = user_data['organizational_unit']
    account.management_login = request.form.get('management_login')
    account.requested = now
    account.created = now
    account.status = Status.created
    account.account_type = AccountType.service
    db.add(account)
    db.commit()

    return redirect('/', code=302)


@app.route('/user_account', methods=['GET'])
@handle_errors
@verify_login
@with_session
def user_account_form(db, user_data):
    return render_template('create_user_account.html', **user_data)



@app.route('/user_account', methods=['POST'])
@with_session
@verify_login
@handle_errors
def user_account_create(db, user_data):
    user = user_data['user']
    now = datetime.now()

    account = Account()
    account.login = request.form.get('login')
    account.password = request.form.get('password')
    account.organizational_unit = user_data['organizational_unit']
    account.requested = now
    account.created = now
    account.status = Status.created
    account.account_type = AccountType[request.form.get('account_type')]
    account.gender = request.form.get('gender')
    account.name_given = request.form.get('name_given')
    account.name_family = request.form.get('name_family')
    account.title = request.form.get('title')
    account.birthday = parse(request.form.get('birthday'))
    account.work_street = request.form.get('work_street')
    account.work_street_no = request.form.get('work_street_no')
    account.work_post_code = request.form.get('work_post_code')
    account.work_city = request.form.get('work_city')
    account.work_phone = request.form.get('work_phone')
    account.private_street = request.form.get('private_street')
    account.private_street_no = request.form.get('private_street_no')
    account.private_post_code = request.form.get('private_post_code')
    account.private_city = request.form.get('private_city')
    account.private_email = request.form.get('private_email')
    account.private_phone = request.form.get('private_phone')
    db.add(account)
    db.commit()

    return redirect('/', code=302)


@app.route('/invite_user', methods=['GET'])
@handle_errors
@verify_login
@with_session
def invite_user_form(db, user_data):
    return render_template('create_user_invite.html', **user_data)


@app.route('/invite_user', methods=['POST'])
@with_session
@handle_errors
def user_invite_create(db):
    i18n = __i18n[request.accept_languages.best_match(__languages)]
    user = session.get('login')[0]
    ou = organizational_unit(user)
    now = datetime.now()
    invitation_key = 'oYS1wcFvO93G9enIkB97mLMqAjkqfvglUtWBdLL4rJSlqmMe'

    account = Account()
    account.login = request.form.get('login')
    account.organizational_unit = ou
    account.requested = now
    account.status = Status.invited
    account.account_type = AccountType[request.form.get('account_type')]
    account.name_given = request.form.get('name_given')
    account.name_family = request.form.get('name_family')
    account.work_street = request.form.get('work_street')
    account.work_street_no = request.form.get('work_street_no')
    account.work_post_code = request.form.get('work_post_code')
    account.work_city = request.form.get('work_city')
    account.work_phone = request.form.get('work_phone')
    account.invitation_key = invitation_key
    db.add(account)
    db.commit()

    invitation_link = f'/invite/{invitation_key}'

    return render_template('user_invite.html', i18n=i18n, user=user,
                           invitation_link=invitation_link)


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/api/exists/<user>', methods=['GET'])
@verify_login
@with_session
def api_login_exists(db, user, user_data):
    local_user = bool(db.query(Account).filter(Account.login == user).first())
    return jsonify(local_user or check_login(user))


init()
