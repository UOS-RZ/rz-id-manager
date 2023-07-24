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

from dateutil.parser import parse
from flask import Flask, request, redirect, render_template, session, jsonify
from functools import wraps
from ldap3.core.exceptions import LDAPBindError, LDAPPasswordIsMandatoryError

from uosrzidmgr.config import config
from uosrzidmgr.ldap import ldap_login, check_login, check_for_user
from uosrzidmgr.db import with_session, Account, Status, AccountType, Action
from uosrzidmgr.mail import mail
from uosrzidmgr.utils import random_string, organizational_unit


# Logger
logger = logging.getLogger(__name__)

flask_config = {}
if config('ui', 'directories', 'template'):
    flask_config['template_folder'] = config('ui', 'directories', 'template')
if config('ui', 'directories', 'static'):
    flask_config['static_folder'] = config('ui', 'directories', 'static')
app = Flask(__name__, **flask_config)
app.secret_key = config('secret_key') or random_string(64)

__error = {}
__i18n = {}
__languages = []


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
        user, email, csrf_token = session.get('login') or ([None] * 3)
        if not user:
            return render_template('login.html', i18n=i18n)

        ou = organizational_unit(user)
        super_admin = user in (config('super_admins') or [])

        data = {'i18n': i18n,
                'csrf_token': csrf_token,
                'organizational_unit': ou,
                'user': user,
                'email': email,
                'super_admin': super_admin}
        return function(*args, user_data=data, **kwargs)
    return wrapper


def assert_org(user_data, account):
    if user_data['super_admin']:
        return
    if account.organizational_unit == user_data['organizational_unit']:
        return
    raise Exception('You are not allowed to manage this account')


@app.route('/', methods=['GET'])
@handle_errors
@verify_login
@with_session
def home(db, user_data):
    ou = user_data['organizational_unit']
    users = db.query(Account).where(Account.organizational_unit == ou)
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
    csrf_token = random_string(32)
    session['login'] = (user, email, csrf_token)

    return redirect('/', code=302)


@app.route('/admin', methods=['GET'])
@handle_errors
@verify_login
@with_session
def admin(db, user_data):
    if not user_data['super_admin']:
        raise Exception()
    users = db.query(Account)
    actions = db.query(Action).order_by(Action.date.desc())
    return render_template('admin.html', users=users, actions=actions,
                           **user_data)


@app.route('/service_account', methods=['GET'])
@handle_errors
@verify_login
def service_account_form(user_data):
    return render_template('service_account_create_form.html', **user_data)


@app.route('/service_account', methods=['POST'])
@with_session
@verify_login
@handle_errors
def service_account_create(db, user_data):
    if user_data['csrf_token'] != request.form.get('csrf_token'):
        raise RuntimeError('CSRF token mismatch')

    login = request.form.get('login')
    if check_login(login):
        raise RuntimeError('User with given username already exists')

    management_login = request.form.get('management_login')
    if not check_login(management_login):
        raise RuntimeError('Management login does not exist.')

    account = Account()
    account.login = login
    account.password = request.form.get('password')
    account.initial_password = random_string(24)
    account.organizational_unit = user_data['organizational_unit']
    account.management_login = management_login
    account.status = Status.created
    account.account_type = AccountType.service
    db.add(account)

    db.add(Action(login, user_data['user'], Status.created))
    db.commit()

    return render_template('service_account_created.html', account=account,
                           **user_data)


@app.route('/user_account', methods=['GET'])
@handle_errors
@verify_login
@with_session
def user_account_form(db, user_data):
    return render_template('user_account_create_form.html', **user_data)


@app.route('/user_account', methods=['POST'])
@with_session
@verify_login
@handle_errors
def user_account_create(db, user_data):
    if user_data['csrf_token'] != request.form.get('csrf_token'):
        raise RuntimeError('CSRF token mismatch')

    login = request.form.get('login')
    if check_login(login):
        raise RuntimeError('User with given username already exists')

    existing_account = request.form.get('existing_account').strip() or None
    name_given = request.form.get('name_given')
    name_family = request.form.get('name_family')
    birthday = parse(request.form.get('birthday'))
    birthday_numerical = birthday.strftime('%Y%m%d')

    request_only = bool(
            existing_account
            or check_for_user(name_given, name_family, birthday_numerical))
    logger.debug('Account creation needs to be approved: %s', request_only)

    account = Account()
    account.existing_account = existing_account
    account.login = login
    account.status = Status.created
    account.initial_password = random_string(24)
    account.organizational_unit = user_data['organizational_unit']
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

    action = Action(login, user_data['user'], Status.created)

    if request_only:
        action.action = Status.requested
        account.status = Status.requested
        mail('User Account', 'User account needs to be approved:\n\n'
             'http://127.0.0.1:5000/check/' + login)
    db.add(action)
    db.add(account)
    db.commit()

    if not request_only:
        logger.warn('TODO: Create account in LDAP')

    return render_template('user_account_createed.html',
                           created=not request_only,
                           account=account,
                           **user_data)


@app.route('/invite_user', methods=['GET'])
@handle_errors
@verify_login
@with_session
def invite_user_form(db, user_data):
    return render_template('user_account_invite_form.html', **user_data)


@app.route('/invite_user', methods=['POST'])
@handle_errors
@verify_login
@with_session
def user_invite_create(db, user_data):
    if user_data['csrf_token'] != request.form.get('csrf_token'):
        raise RuntimeError('CSRF token mismatch')

    ou = user_data['organizational_unit']
    invitation_key = random_string(64)
    login = request.form.get('login')

    account = Account()
    account.login = login
    account.initial_password = random_string(24)
    account.organizational_unit = ou
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

    db.add(Action(login, user_data['user'], Status.invited))
    db.commit()

    invitation_link = f'/invite/{invitation_key}'

    return render_template('user_account_invite_created.html',
                           invitation_link=invitation_link, **user_data)


@app.route('/invite_link/<login>', methods=['GET'])
@handle_errors
@verify_login
@with_session
def user_invite_link(db, user_data, login):
    account = db.query(Account)\
            .where(Account.login == login)\
            .one()
    assert_org(user_data, account)

    invitation_link = f'/invite/{account.invitation_key}'

    return render_template('user_account_invite_created.html',
                           invitation_link=invitation_link, **user_data)


@app.route('/invite/<invitation_key>', methods=['GET'])
@handle_errors
@with_session
def invite_user_accept_form(db, invitation_key):
    i18n = __i18n[request.accept_languages.best_match(__languages) or 'en']
    account = db.query(Account)\
                .where(Account.invitation_key == invitation_key)\
                .one()
    return render_template('user_account_invite_accept_form.html', i18n=i18n,
                           account=account, invitation_key=invitation_key)


@app.route('/user_account_invite', methods=['POST'])
@with_session
@handle_errors
def user_account_create_from_invite(db):
    i18n = __i18n[request.accept_languages.best_match(__languages) or 'en']

    invitation_key = request.form.get('invitation_key')
    account = db.query(Account)\
                .where(Account.invitation_key == invitation_key)\
                .one()

    existing_account = request.form.get('existing_account').strip() or None
    name_given = request.form.get('name_given')
    name_family = request.form.get('name_family')
    birthday = parse(request.form.get('birthday'))
    birthday_numerical = birthday.strftime('%Y%m%d')

    request_only = bool(
            existing_account
            or check_for_user(name_given, name_family, birthday_numerical))
    logger.debug('Account creation needs to be approved: %s', request_only)

    account.existing_account = existing_account
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

    action = Action(account.login, account.login, Status.created)

    if request_only:
        action.action = Status.requested
        account.status = Status.requested
        mail('User Account', 'User account needs to be approved:\n\n'
             'http://127.0.0.1:5000/check/' + login)
    else:
        account.status = Status.created

    db.add(action)
    db.commit()

    if not request_only:
        logger.warn('TODO: Create account in LDAP')

    return render_template('user_account_createed.html', i18n=i18n,
                           created=not request_only,
                           account=account)


@app.route('/info/<login>', methods=['GET'])
@handle_errors
@verify_login
@with_session
def account_info(db, user_data, login):
    account = db.query(Account)\
            .where(Account.login == login)\
            .one()

    assert_org(user_data, account)

    template = 'service_account_info.html' \
        if account.account_type == AccountType.service \
        else 'user_account_review.html'
    return render_template(template, account=account,
                           **user_data)


@app.route('/check/<login>', methods=['GET'])
@handle_errors
@verify_login
@with_session
def check_request(db, user_data, login):
    if not user_data['super_admin']:
        raise Exception('Only super admins are allowed to accept requests')

    account = db.query(Account)\
                .where(Account.login == login)\
                .one()

    potential_conflicts = []
    if account.existing_account:
        potential_conflicts.append(account.existing_account)
    potential_conflicts += check_for_user(account.name_given,
                                          account.name_family,
                                          account.birthday.strftime('%Y%m%d'))

    return render_template('user_account_review.html', account=account,
                           potential_conflicts=potential_conflicts,
                           can_approve=True,
                           **user_data)


@app.route('/cancel/<login>', methods=['GET'])
@handle_errors
@verify_login
@with_session
def cancel_form(db, user_data, login):
    account = db.query(Account)\
            .where(Account.login == login)\
            .one()

    assert_org(user_data, account)

    if account.status not in [Status.invited, Status.requested]:
        raise Exception('Cannot cancel accounts in status %s', account.status)

    return render_template('user_account_cancel_confirm.html', account=account,
                           **user_data)


@app.route('/cancel', methods=['POST'])
@handle_errors
@verify_login
@with_session
def cancel(db, user_data):
    login = request.form.get('login')
    account = db.query(Account)\
                .where(Account.login == login)\
                .one()

    assert_org(user_data, account)

    if account.status not in [Status.invited, Status.requested]:
        raise Exception('Cannot cancel accounts in status %s', account.status)

    account.status = Status.cancelled
    db.add(Action(login, user_data['user'], Status.cancelled))
    db.commit()

    return redirect('/', code=302)


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
