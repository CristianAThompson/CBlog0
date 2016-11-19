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
import webapp2, jinja2, os

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

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# Blog Content
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Blog(db.Model):
    # title = db.StringProperty(required = True)
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

class MainHandler(Handler):

    def get(self):
        blogs = db.GqlQuery("SELECT * from Blog ORDER BY created DESC LIMIT 10")
        self.render('blog.html', blogs = blogs)

class PostPageHandler(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
        self.render('perma.html', post = post)

class NewPostHandler(Handler):
    def get(self):
        self.render('newpost.html')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            b = Blog(parent = blog_key(), subject = subject, content = content)
            b.put()
            self.redirect('/id=%s' % str(b.key().id()))
        else:
            error = "Make sure you included both fields."
            self.render('newpost.html', subject = subject, content = content, error = error)


app = webapp2.WSGIApplication([('/', MainHandler),
                                ('/newpost', NewPostHandler),
                                ('/id=([0-9]+)', PostPageHandler)], debug=True)
