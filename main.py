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
import webapp2, jinja2, os, random, string, hmac, hashlib, re, time

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

# Define the base Handler class that allows quick usage of the webapp2.requestHandler
# also defines some base methods and check and validates the cookie
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

# Secret used in conjunction with make_secure function
secret = "fha8972hkfw098y"

# Create a secure tuple of a passed in string of the string and hmac encoded version of string
def make_secure(s):
    return '%s|%s' % (s, hmac.new(secret, s).hexdigest())

# Splits the passed in value and takes the first index to compare against itself passed in to make_secure function
def check_secure(h):
    value = h.split("|")[0]
    if h == make_secure(value):
        return value

# Create a random salt value of any 5 letters
def make_salt():
    salted = ''.join(random.choice(string.letters) for x in xrange(5))
    return salted

# Takes in user information and if it contains a salt uses the stored salt
# to create a hashed password of the username password and salt passed encoded in sha256
# if no salt is declared, or present in user information run make_salt to create one
def make_pw_hash(username, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(username + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

# Checks the hashed password against the stored user credentials splits the h value
# and uses index location 1 as a variable to compare against for verification that it hasn't been tampered with
def valid_pw(name, pw, h):
    salt = h.split('|')[1]
    return h == make_pw_hash(name, pw, salt)

# Dictates where a user is directed if they are signed in or not and accesses the
# page from the base url
class DefaultPageHandler(Handler):
    def get(self):
        if self.user:
            self.redirect('/blog')
        else:
            self.redirect('/login')

# Defines the Blog Entity and what it will store
class Blog(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    submitted_user = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    likes = db.StringProperty()
    like_total = db.IntegerProperty()

# Defines the User Entity and several functions specifically tied to User entities
class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()

    # Retreives the specific user by the id passed in
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    # Retreives a user from the User database where the username is the passed in username
    @classmethod
    def by_name(cls, username):
        u = User.all().filter('username = ', username).get()
        return u

    # Shorthand for creating a user entity with passed in username and password
    @classmethod
    def register(cls, username, pw, email = None):
        pw_hash = make_pw_hash(username, pw)
        return User(username = username,
                    password = pw_hash,
                    email = email)

    # Verifies that the passed in username and the stored hashed password are True
    # then logs in
    @classmethod
    def login(cls, username, pw):
        u = cls.by_name(username)
        if u and valid_pw(username, pw, u.password):
            return u

# Defines the Comment database entity and what each entity will contain
class Comment(db.Model):
    comment_username = db.StringProperty(required = True)
    comment_content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    post_id = db.IntegerProperty(required = True)
    parent_id = db.IntegerProperty(required = True)

# Defines the default page and if user is signed in retrieve that users blog posts
class MainHandler(Handler):

    def get(self):
        if self.user:
            userid = make_secure(self.user.username)
            blogs = Blog.all().filter('submitted_user =', userid).order('-created')
            self.render('blog.html', blogs = blogs, username = self.user.username)
        else:
            self.redirect('/login')

# Defines the perma link post pages
class PermaHandler(Handler):

    # Retrieves and manages the content displayed on the permalink page based upon
    # what user is accessing the page
    def get(self, post_id):
        # Retrieve the specific Blog entry and all comments for that entry with the post_id from the url
        key = db.Key.from_path('Blog', int(post_id))
        post = db.get(key)
        comments = Comment.all().filter('post_id =', int(post_id))

        # If the id isn't valid return a 404 error
        if not post:
            self.error(404)
            return
        if self.user:
            post_owner = make_secure(self.user.username)
            self.render('perma.html', post = post, username = self.user.username, comments = comments, post_owner = post_owner)
        else:
            no_user = "Please Sign In To Comment or Like this post!"
            self.render('perma.html', post = post, comments = comments, no_user = no_user)

    # Defines the functionality of the comment submission form for users who wish to leave a comment
    def post(self, post_id):
        key = db.Key.from_path('Blog', int(post_id))
        post = db.get(key)
        comments = Comment.all().filter('post_id=', int(post_id))

        username = self.user.username
        content = self.request.get('comment_content')

        # If content is present and is a signed in user then creates new comment entity with the user submitted information
        if content and self.user:
            comment = Comment(comment_username = username, comment_content = content, post_id = int(post_id), parent_id = int(post.key().id()))
            comment.put()
            time.sleep(.3)
            self.redirect('/id=%s' % str(post.key().id()))
        else:
            cerror = "Make sure you added a comment before you submitted."
            self.render('perma.html', post = post, username = username, comments = comments, comment_error = cerror)

# Defines the functionality of the New Post Page
class NewPostHandler(Handler):
    def get(self):
        if self.user:
            self.render('newpost.html', username = self.user.username)
        else:
            self.redirect('/')

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

# Regular expressions for comparison when creating a new user
uname = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
upass = re.compile(r"^.{3,20}$")
uemail = re.compile(r"[\S]+@[\S]+.[\S]+$")

# Tests taking in submitted user data and comparing it against regular expressions
def valid_username(username):
    return uname.match(username)

def valid_password(password):
    return upass.match(password)

def valid_email(email):
    return uemail.match(email)

# Takes in Handler base class and renders a form page for user creation
class SignUpHandler(Handler):

    # If there is already a user trying to access the page it redirects to blog
    # otherwise render the user submission form
    def get(self):
        if self.user:
            self.redirect('/')
        else:
            self.render('sign-up.html')

    # Defines the post method with the information submitted by the user
    def post(self):

        # Retrieve the user submitted data and a value to compare against for validation
        error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        params = dict(username = self.username, email = self.email)

        # If not a valide username against the regular expression define error and an error parameter
        if not valid_username(self.username):
            params['nerror'] = "You entered an invalid Username, please try again."
            error = True

        # If not a valide password against the regular expression define error and an error parameter
        if not valid_password(self.password):
            params['perror'] = "You typed an invalid password, please try again."
            error = True

        # If the user submitted password doesn't match the second password define error and an error parameter
        elif self.password != self.verify:
            params['perror'] = "Your passwords didn't match, please try again."
            error = True

        # If there is an email present check it against the regular expression
        # if not valid define error and an error parameter
        if self.email:
            if not valid_email(self.email):
                params['eerror'] = "You entered an invalid email, please try again."
                error = True

        # If error is present then re-render the sign-up form with the parameters
        # or else run the function done()
        if error:
            self.render('sign-up.html', **params)
        else:
            self.done()

    # Raises an error when not re-defined to accomplish something else.
    def done(self, *a, **kw):
        raise NotImplementedError

# Uses the SignUpHandler instead of Handler and redefines the done function
class RegisterPage(SignUpHandler):
    def done(self):
        # Make database query with the username just created
        u = User.by_name(self.username)
        # If there is a user with that username raise an error and re-render form
        if u:
            exists = 'That user already exists.'
            self.render('sign-up.html', nerror = exists)
        # Take user submitted data and format it for the User entity, place the formatted data
        # inside the User entity and redirect to the welcome page
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')

# Takes in Handler and renders a welcome page if there is a user signed in
# or the sign-up page when one isn't signed in
class WelcomeHandler(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.username)
        else:
            self.redirect('/signup')

# Takes in Handler and renders a login form, then retrieves that data after submission
# and checks if the username and password are correct, if correct redirect to the blog,
# if not correct re-render login form with an error
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

# Removes User Cookie information to sign them out of the account
class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/blog')

# Takes Handler renders an edit page if the user signed in is the same user that
# created the post
class EditPage(Handler):

    def get(self, post_id):

        # Retrieve the specific blog entry from the post_id which maps to the id integer in the url
        key = db.Key.from_path('Blog', int(post_id))
        post = db.get(key)

        # Verify that the submitted user and the currently signed in user are the same
        # if they are render an edit form with the content of the post passed in,
        # if they don't match redirect to the perma-link of the post
        if post.submitted_user == make_secure(self.user.username):
            if not post:
                self.error(404)
                return
            if self.user:
                self.render('edit.html', post = post, username = self.user.username)
        else:
            self.redirect('/id=%s' % str(post.key().id()))

    # Capture the form submission from the edit page and resubmit the blog post to the database
    def post(self, post_id):

        # Retrieve the specific blog entry from the post_id which maps to the id integer in the url
        key = db.Key.from_path('Blog', int(post_id))
        post = db.get(key)

        # Capture subject and content from submission
        subject = self.request.get('subject')
        content = self.request.get('content')

        # If both subject and content are present re-define the current post content
        # with the newly submitted content and place it back within the Blog entity
        # then redirect to the perma-link
        if subject and content:
            post.content = content
            post.put()
            time.sleep(.2)
            self.redirect('/id=%s' % str(post.key().id()))
        # If both subject and content aren't present define an error and re-render
        # the form with that error
        else:
            error = "Make sure you included both fields."
            self.render('edit.html', post = post, error = error)

# Defines the edit comment functionality
class EditComment(Handler):

    # Retrieve the specific comment ID and with it fill the edit form
    def get(self, post_id):
        # Retrieve the comment entry
        key = db.Key.from_path('Comment', int(post_id))
        post = db.get(key)
        # If there is a user and that user is the person who created the comment
        # render the page with the comment information inside the form fields if
        # not redirect to the original post
        if self.user:
            if post.comment_username == self.user.username:
                self.render('editcomment.html', post = post, username = self.user.username)
            else:
                self.redirect('/id=%s' % post.parent_id)
        else:
            self.redirect('/id=%s' % post.parent_id)

    # Retrieve the specific comment and if the content has changed replace the
    # content stored for that comment and redirect to the original post
    def post(self, post_id):

        key = db.Key.from_path('Comment', int(post_id))
        post = db.get(key)

        content = self.request.get('content')

        if content:
            post.comment_content = content
            post.put()
            time.sleep(.2)
            self.redirect('/id=%s' % post.parent_id)
        else:
            error = "Make sure you have content in the box."
            self.render('editcomment.html', post = post, error = error, username = self.user.username)

# Retrieve the specific blog post by ID and if the submitted user and the hashed
# currently logged in user match then use the built in delete function on the entity
# and redirct to the main blog page
class Delete(Handler):

    def get(self, post_id):

        key = db.Key.from_path('Blog', int(post_id))
        post = db.get(key)

        if post.submitted_user == make_secure(self.user.username):
            post.delete()
            time.sleep(.2)
            self.redirect('/blog')
        else:
            self.redirect('/blog')

# Retrieve the comment entry by ID and if the comment creator and the currently
# logged in user match then use the built in delete to remove the entry and redirect
# back to the orignal post
class DeleteComment(Handler):

    def get(self, post_id):

        key = db.Key.from_path('Comment', int(post_id))
        post = db.get(key)

        if self.user:
            if post.comment_username == self.user.username:
                post.delete()
                time.sleep(.2)
                self.redirect('/id=%s' % post.parent_id)
            else:
                self.redirect('/id=%s' % post.parent_id)
        else:
            self.redirect('/id=%s' % post.parent_id)

# Define the functionality behind likes and how they are stored.
class LikePost(Handler):

    def get(self, post_id):

        # Retrieve the specific blog post
        key = db.Key.from_path('Blog', int(post_id))
        post = db.get(key)

        # If the user is signed in and not the post owner and there are already
        # likes then add current user to the likes entry and add one to the likes
        # total if the user has already liked the post then remove name from likes
        # and reduce the likes total by 1
        if self.user:
            if post.likes:
                if make_secure(self.user.username) != post.submitted_user:
                    if self.user.username not in post.likes:
                        post.likes += self.user.username
                        post.like_total +=1
                        post.put()
                    elif self.user.username in post.likes:
                        post.likes = str(post.likes).replace(self.user.username, "")
                        post.like_total -=1
                        post.put()
            # If there are no likes present and the current user isn't the post author
            # then create likes with the current username and create likes total
            # with a value of 1
            else:
                if make_secure(self.user.username) != post.submitted_user:
                    post.likes = self.user.username
                    post.like_total = 1
                    post.put()

        self.redirect('/id=%s' % str(post.key().id()))









app = webapp2.WSGIApplication([('/', DefaultPageHandler),
                                ('/blog', MainHandler),
                                ('/newpost', NewPostHandler),
                                ('/id=([0-9]+)', PermaHandler),
                                ('/edit/id=([0-9]+)', EditPage),
                                ('/editcomment/id=([0-9]+)', EditComment),
                                ('/like/id=([0-9]+)', LikePost),
                                ('/signup', RegisterPage),
                                ('/login', LoginPage),
                                ('/logout', Logout),
                                ('/delete/id=([0-9]+)', Delete),
                                ('/commentdelete/id=([0-9]+)', DeleteComment),
                                ('/welcome', WelcomeHandler)], debug=True)
