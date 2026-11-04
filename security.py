"""Security controls shared by the existing routes. No profile data in cookies."""
import hashlib
import hmac
import os
import re
import secrets
import time
from datetime import datetime,timedelta
from functools import wraps
from flask import abort,current_app,g,redirect,render_template,request,session,url_for
from mysql.connector import Error
from werkzeug.exceptions import HTTPException,SecurityError
from database import query,execute,transaction,close_db

UID=re.compile(r'^[0-9]{2}[a-z]{2,5}[0-9]{4,6}$')


def identity(uid,email):
    uid,email=uid.strip().lower(),email.strip().lower()
    if not UID.fullmatch(uid):
        raise ValueError('Enter a valid CU UID, for example 25bit10108.')
    if email!=uid+'@cuchd.in':
        raise ValueError('University email must match your UID followed by @cuchd.in.')
    return uid,email


def digest(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def begin_session(user_id):
    token=secrets.token_urlsafe(32)
    with transaction():
        execute('INSERT INTO auth_sessions (session_hash,user_id,expires_at) VALUES (%s,%s,%s)',(digest(token),user_id,datetime.now()+current_app.permanent_session_lifetime))
    session.clear()
    session.update(user_id=user_id,auth_token=token,csrf=secrets.token_urlsafe(32))
    session.permanent=True


def revoke_session():
    token=session.get('auth_token')
    if isinstance(token,str):
        with transaction():
            execute('UPDATE auth_sessions SET revoked_at=NOW() WHERE session_hash=%s AND user_id=%s AND revoked_at IS NULL',(digest(token),session.get('user_id')))
    session.clear()


def role_required(role):
    def decorate(fn):
        @wraps(fn)
        def wrapped(*args,**kwargs):
            if not g.user:
                return redirect(url_for('login'))
            if g.user['role']!=role:
                abort(403)
            return fn(*args,**kwargs)
        return wrapped
    return decorate


def rate_limit():
    if request.method!='POST' or not current_app.config['RATE_LIMIT_ENABLED']:
        return None
    address=request.remote_addr or 'unknown'
    if request.endpoint=='login':
        identifier=request.form.get('identifier',request.form.get('email','')).strip().lower()
        account=identifier[:-9] if identifier.endswith('@cuchd.in') else identifier
        rules=[('login-ip',address,30,60),('login-account',account[:254],8,60)]
    elif request.endpoint=='register':
        rules=[('register-ip',address,20,3600)]
    elif request.endpoint in ('student.save_apply','admin.review') and g.get('user'):
        rules=[(request.endpoint,str(g.user['user_id']),30 if request.endpoint=='student.save_apply' else 60,60)]
    else:
        return None
    now=int(time.time())
    retry=0
    with transaction():
        for scope,value,limit,seconds in rules:
            if current_app.config.get('RATE_LIMIT_TEST_RULE'):
                limit,seconds=current_app.config['RATE_LIMIT_TEST_RULE']
            key=hmac.new(current_app.secret_key.encode('utf-8'),f'{scope}:{value}'.encode('utf-8'),hashlib.sha256).hexdigest()
            execute('INSERT INTO security_rate_limits (bucket_key,window_start,hits) VALUES (%s,%s,0) ON DUPLICATE KEY UPDATE bucket_key=bucket_key',(key,now))
            row=query('SELECT window_start,hits FROM security_rate_limits WHERE bucket_key=%s FOR UPDATE',(key,),one=True)
            start,hits=row['window_start'],row['hits']
            if now>=start+seconds:
                start,hits=now,0
            if hits>=limit:
                retry=max(retry,start+seconds-now)
            else:
                execute('UPDATE security_rate_limits SET window_start=%s,hits=%s WHERE bucket_key=%s',(start,hits+1,key))
    return retry or None


def configure(app):
    is_vercel=bool(os.getenv('VERCEL') or os.getenv('VERCEL_ENV'))
    production=(os.getenv('APP_ENV','development').lower()=='production') or is_vercel
    key=app.secret_key
    if not key or len(key)<32 or key.startswith(('replace-','change-')):
        raise RuntimeError('Configure a private FLASK_SECRET_KEY of at least 32 characters in .env.')
    
    trusted_hosts=['127.0.0.1','localhost','[::1]']
    if production:
        explicit_hosts=[host.strip() for host in os.getenv('TRUSTED_HOSTS','').split(',') if host.strip()]
        hosts=list(explicit_hosts)
        if is_vercel:
            hosts.extend(['.vercel.app','campus-opportunity-plan-cu.vercel.app'])
            for v_env in ('VERCEL_URL','VERCEL_PROJECT_PRODUCTION_URL'):
                vh=os.getenv(v_env,'').strip()
                if vh and vh not in hosts:
                    hosts.append(vh)
        else:
            for v_env in ('VERCEL_URL','VERCEL_PROJECT_PRODUCTION_URL'):
                vh=os.getenv(v_env,'').strip()
                if vh and vh not in explicit_hosts and vh not in hosts:
                    hosts.append(vh)
            db_user=os.getenv('DB_USER','root').lower()
            if not explicit_hosts or db_user=='root':
                raise RuntimeError('Production requires TRUSTED_HOSTS and a dedicated non-root database user.')
        trusted_hosts.extend(hosts)
        trusted_hosts=list(dict.fromkeys(trusted_hosts))
    elif is_vercel:
        trusted_hosts.extend(['.vercel.app','campus-opportunity-plan-cu.vercel.app'])
        trusted_hosts=list(dict.fromkeys(trusted_hosts))

    app.config.update(DEBUG=False,PRODUCTION=production,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=production,PERMANENT_SESSION_LIFETIME=timedelta(hours=8),MAX_CONTENT_LENGTH=1024*1024,
        MAX_FORM_MEMORY_SIZE=256*1024,MAX_FORM_PARTS=500,RATE_LIMIT_ENABLED=True,
        TRUSTED_HOSTS=trusted_hosts)
    app.teardown_appcontext(close_db)

    @app.before_request
    def protect_request():
        g.user=None
        if isinstance(request.routing_exception,SecurityError):
            return render_template('invalid_request.html'),400
        if app.config['PRODUCTION'] and not (request.is_secure or request.headers.get('X-Forwarded-Proto','').lower()=='https'):
            return render_template('security_error.html',title='HTTPS required',message='Use the secure HTTPS application address.'),400
        session.setdefault('csrf',secrets.token_urlsafe(32))
        if request.method in ('POST','PUT','PATCH','DELETE'):
            supplied=request.headers.get('X-CSRF-Token') or request.form.get('csrf_token','')
            expected=session.get('csrf')
            if not isinstance(expected,str) or len(supplied)>128 or not secrets.compare_digest(expected.encode('utf-8'),supplied.encode('utf-8')):
                return render_template('security_error.html',title='Form expired',message='Refresh this page and try again.'),400
        if session.get('user_id'):
            token=session.get('auth_token')
            if isinstance(token,str) and len(token)<=100:
                g.user=query('''SELECT u.user_id,u.full_name,u.email,u.role,u.is_active FROM users u JOIN auth_sessions s ON s.user_id=u.user_id
                    WHERE u.user_id=%s AND s.session_hash=%s AND s.revoked_at IS NULL AND s.expires_at>NOW()''',(session['user_id'],digest(token)),one=True)
            if not g.user or not g.user['is_active']:
                g.user=None
                session.clear()
                return redirect(url_for('login'))
        retry=rate_limit()
        if retry:
            app.logger.warning('security_event=rate_limit endpoint=%s',request.endpoint)
            return render_template('security_error.html',title='Please slow down',message='Too many attempts. Wait before trying again.'),429,{'Retry-After':str(retry)}

    @app.context_processor
    def context():
        return {'current_user':g.get('user'),'csrf_token':lambda:session.get('csrf','')}

    @app.after_request
    def headers(response):
        response.headers.update({
            'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'",
            'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'same-origin',
            'Permissions-Policy':'camera=(), microphone=(), geolocation=(), payment=()', 'Cache-Control':'no-store'})
        if app.config['PRODUCTION'] and request.is_secure:
            response.headers['Strict-Transport-Security']='max-age=31536000'
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        if isinstance(error,SecurityError):
            return render_template('invalid_request.html'),400
        response=error.get_response()
        response.set_data(render_template('security_error.html',title=str(error.code),message={400:'This request could not be accepted.',403:'You do not have access to this page.',404:'This page was not found.',405:'This action requires a different request method.',413:'This request is too large.',500:'The service could not complete this request.'}.get(error.code,'This request could not be completed.')))
        response.content_type='text/html; charset=utf-8'
        return response

    @app.errorhandler(Error)
    def db_error(error):
        app.logger.error('security_event=database_error type=%s',type(error).__name__)
        return render_template('security_error.html',title='Service unavailable',message='The database operation could not be completed. Try again later.'),503

    @app.errorhandler(Exception)
    def unexpected_error(error):
        app.logger.error('security_event=request_error type=%s endpoint=%s',type(error).__name__,request.endpoint)
        return render_template('security_error.html',title='Service error',message='This request could not be completed. Try again later.'),500
