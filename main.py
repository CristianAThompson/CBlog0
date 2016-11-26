#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2, jinja2, os, random, string, hmac, hashlib, re

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_cookie(self, name, val):
        cookie_val = make_secure(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure(cookie_val)

    def login(self, user):
        self.set_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

secret = "fha8972hkfw098y"

def make_secure(s):
    return '%s|%s' % (s, hmac.new(secret, s).hexdigest())

def check_secure(h):
    value = h.split("|")[0]
    if h == make_secure(value):
        return value

def make_salt():
    salted = ''.join(random.choice(string.letters) for x in xrange(5))
    return salted

def make_pw_hash(username, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(username + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split('|')[1]
    return h == make_pw_hash(name, pw, salt)

# Blog Content
class DefaultPageHandler(Handler):
    def get(self):
        if self.user:
            self.redirect('/blog')
        else:
            self.redirect('/login')

class Blog(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    submitted_user = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, username):
        u = User.all().filter('username = ', username).get()
        return u

    @classmethod
    def register(cls, username, pw, email = None):
        pw_hash = make_pw_hash(username, pw)
        return User(username = username,
                    password = pw_hash,
                    email = email)

    @classmethod
    def login(cls, username, pw):
        u = cls.by_name(username)
        if u and valid_pw(username, pw, u.password):
            return u

class MainHandler(Handler):

    def get(self):
        if self.user:
            userid = make_secure(self.user.username)
            blogs = Blog.all().filter('submitted_user =', userid)
            self.render('blog.html', blogs = blogs, username = self.user.username)
        else:
            self.redirect('/login')

class PostPageHandler(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Blog', int(post_id))
        post = db.get(key)

        if not post:
            self.error(404)
            return
        if self.user:
            self.render('perma.html', post = post, username = self.user.username)
        else:
            self.render('perma.html', post = post)

class NewPostHandler(Handler):
    def get(self):
        if self.user:
            self.render('newpost.html', username = self.user.username)

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            b = Blog(subject = subject, content = content, submitted_user = make_secure(self.user.username))
            b.put()
            self.redirect('/id=%s' % str(b.key().id()))
        else:
            error = "Make sure you included both fields."
            self.render('newpost.html', subject = subject, content = content, error = error)

uname = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
upass = re.compile(r"^.{3,20}$")
uemail = re.compile(r"[\S]+@[\S]+.[\S]+$")

def valid_username(username):
    return uname.match(username)

def valid_password(password):
    return upass.match(password)

def valid_email(email):
    return uemail.match(email)

class SignUpHandler(Handler):

    def get(self):
        self.render('sign-up.html')

    def post(self):

        error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        params = dict(username = self.username, email = self.email)

        if not valid_username(self.username):
            params['nerror'] = "You entered an invalid Username, please try again."
            error = True

        if not valid_password(self.password):
            params['perror'] = "You typed an invalid password, please try again."
            error = True
        elif self.password != self.verify:
            params['perror'] = "Your passwords didn't match, please try again."
            error = True

        if self.email:
            if not valid_email(self.email):
                params['eerror'] = "You entered an invalid email, please try again."
                error = True

        if error:
            self.render('sign-up.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class SignUpPage(SignUpHandler):
    def done(self):
        self.redirect('/welcome')

class RegisterPage(SignUpHandler):
    def done(self):
        u = User.by_name(self.username)
        if u:
            exists = 'That user already exists.'
            self.render('sign-up.html', nerror = exists)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')


class WelcomeHandler(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.username)
        else:
            self.redirect('/signup')

class LoginPage(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        loggedin = User.login(username, password)

        if loggedin:
            self.login(loggedin)
            self.redirect('/blog')
        else:
            error = "That wasn't a valid user!"
            self.render('login.html', error = error)

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/blog')


app = webapp2.WSGIApplication([('/', DefaultPageHandler),
                                ('/blog', MainHandler),
                                ('/newpost', NewPostHandler),
                                ('/id=([0-9]+)', PostPageHandler),
                                ('/signup', RegisterPage),
                                ('/login', LoginPage),
                                ('/logout', Logout),
                                ('/welcome', WelcomeHandler)], debug=True)
