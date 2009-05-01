import cgi, re, os, random, sha, time, functools, datetime, Cookie
import wsgiref.handlers
from google.appengine.ext import webapp
from google.appengine.api import users
from google.appengine.ext import db
from google.appengine.api import mail
from google.appengine.ext.webapp import template

# This is the format of dates in the HTTP header
http_time_format = "%a, %d %b %Y %H:%M:%S GMT"
    
# We set the Content-type and Content-Disposition headers based on file extension.
# This list is not very extensive.
extensions = {
  "png": ("image/png", None),
  "jpg": ("image/jpeg", None),
  "html": ("text/html", "attachment;filename=%s"),
  "gif": ("image/gif", None),
  "css": ("text/css", None),
  "js": ("text/javascript; charset=UTF-8", None),
  "pdf": ("application/pdf", None),
}

# Only files on this list will get served via the ForeverStaticFile handler.
# We'd use the AppEngine static handler, but it doesn't work.
static_files = [ "jquery.js", "style.css" ]

class LearnedUsers(db.Model):
  """Represents users we know about.  Users not in this table are not allowed
  to play in our sandbox (unless they are marked as an Administrator via
  appengine).
  TODO: enforce uniqueness
  """
  invited_by = db.UserProperty()
  fuzzy_email = db.StringProperty()

class SharedObject(db.Model):
  """Represents uploaded files."""
  date = db.DateTimeProperty(auto_now_add=True)
  uploader = db.UserProperty()
  consumer = db.StringProperty()
  filename = db.StringProperty()
  hash = db.StringProperty()
  body = db.BlobProperty()
  secret = db.BooleanProperty()

def replace_unsafe_chars(s):
  """returns s with dangerous characters replaced with an _.
  
  Why: HTTP headers, filenames, and other fields should never contain newlines,
  HTML meta characters, etc.

  For more information, see http://en.wikipedia.org/wiki/HTTP_response_splitting.
  """
  return re.sub("[^a-z0-9_.+-]", "_", s.strip())
  
def is_valid_email(email):
  """Returns True if email looks like a valid email address, 
  and false otherwise.
  """
  if not email:
    return False  
  return re.match("^[a-z0-9.-]+([+][a-z0-9.-]+)?@([a-z0-9-]+[.])+[a-z0-9]+$", 
                  email.strip()) is not None
    
def checkbox_set(fields, field_name):
  """Returns True if the field_name value is "on" """
  return fields.has_key(field_name) and fields[field_name].value == "on"

def verify_xsrf_token(method):
  """Asserts that the request is acceptable per XSRF tests.  If the token is
  not valid, we send a 500.  If it is valid, the wrapped method can assume the
  request is legitimate.
  
  Why: Proper web practice dictates that mutation only occur via POST requests.
  However, I'm lazy, and dealing with POST requires more lines of code and more
  complex javascript than using GETs.
  
  How: The XSRF token allows us to permit mutation via GET requests because the
  presence of the token indicates a request from a trusted source.  We know the
  source is trusted because the token is derived from a cookie which is only
  known to pages on our domain.  This prevents third party pages from creating
  links to actions on our site that mutate data.
  
  For more information, see
  http://en.wikipedia.org/wiki/Cross-site_request_forgery 
  """
  @functools.wraps(method)
  def wrapper(self, *args, **kwargs):
    c = Cookie.Cookie()
    c.load(self.request.headers['Cookie'])
    # The presence of the xt cookie means that the user has had the cookie
    # set.  If the cookie missing, we must reject the request.  In order to not
    # impose constraints on parameter passing of the other methods, we merely
    # look for "xtTOKEN" anywhere in the request URL.
    if not (c.has_key("xt") and ("xt" + c["xt"].value) in self.request.uri):
      self.error(500)
      self.response.out.write("Your cookies are not good to eat.")
      return
    # Tests pass -> the invoked method can assume the XSRF token is legitimate.
    return method(self, *args, **kwargs)
  return wrapper

def cacheliberally(method):
  """Sets an Expires: header of one year and allows intermediate HTTP caches to
  cache the content.
  """
  @functools.wraps(method)
  def wrapper(self, *args, **kwargs):
    self.response.headers['Cache-Control'] = "public"
    year = (datetime.datetime.utcnow() + 
            datetime.timedelta(days=365)).strftime(http_time_format)
    self.response.headers['Expires'] = year
    return method(self, *args, **kwargs)
  return wrapper
    
def loggedin(method):
  """Asserts that a known user is logged in.  If they aren't, we redirect them to
  the login page (if they aren't logged in) or to a "you can't come to our
  party" page if they are logged in but unknown to us.  The wrapped method can
  assume that the user is an acceptable person.
  """
  @functools.wraps(method)
  def wrapper(self, *args, **kwargs):
    user = users.get_current_user()
    if not user:
      # Redirecting non-GETs is likely to cause some undesired behavior, so
      # let's fail early.  This shouldn't happen because the user should already
      # be authenticated if there is any non-GET behavior.
      if self.request.method != "GET":
        self.error(403)
      else:
        self.redirect(users.create_login_url(self.request.uri))
    else:
      # user must be an admin or exist in the invited list
      allowed = False
      if users.is_current_user_admin():
        allowed = True
      else:
        r = LearnedUsers.gql("WHERE fuzzy_email = :1", user.email())
        if r.get():
          allowed = True
      if not allowed:
        self.redirect("/invitationonly")
      else:
        return method(self, *args, **kwargs)
  return wrapper
    
class UploadAction(webapp.RequestHandler):
  """Handles the file upload
  """
  @loggedin
  def post(self):
    user = users.get_current_user()      
    form = cgi.FieldStorage()

    email = form["consumer"].value    

    if form.has_key("file_1"):
      item = form["file_1"]
      data = item.file.read()
      
      if data is not None and len(data):
        o = SharedObject()
        o.filename = replace_unsafe_chars(item.filename)
        o.uploader = user
        o.secret = checkbox_set(form, "secret")
        if is_valid_email(email):
          o.consumer = email
          friend = LearnedUsers()
          friend.fuzzy_email = email
          friend.invited_by = user
          friend.put()

        o.body = db.Blob(str(data))
        o.hash = sha.sha(o.body + o.filename + str(random.random())).hexdigest()
        o.put()

        if is_valid_email(email):
          sender_address = "%s <%s>" % (user.nickname(), user.email())
          subject = "I've uploaded a file for you!"
          template_values = {
            "url": "http://%s/get/%s/%s" % (self.request.headers["Host"], o.hash, o.filename),
            "nickname": user.nickname(),
          }
          path = os.path.join(os.path.dirname(__file__), 'email.txt')
          body = template.render(path, template_values)
          mail.send_mail(sender_address, email, subject, body)

    self.redirect("/")

class GetPage(webapp.RequestHandler): 
  """Returns the object from the datastore
  """
  @cacheliberally 
  def get(self, hash, filename):    
    query = SharedObject.all()
    query.order("-date")
    query.filter("hash = ", hash)
    query.filter("filename = ", filename)
    item = query.fetch(1)[0]
    self.response.out.write(item.body)

    t = 'text/plain'
    d = None
    
    extension = filename.split(".").pop()
    if extensions.has_key(extension):
      t, d = extensions[extension]
      if d:
        self.response.headers['Content-Disposition'] = d % (
          replace_unsafe_chars(filename))

    self.response.headers['Content-Type'] = t
    self.response.headers['Last-Modified'] = item.date.strftime(http_time_format)                                                           
class RemoveAction(webapp.RequestHandler):
  """Removes a file from the list.
  """
  @loggedin
  @verify_xsrf_token
  def get(self, hash, token): 
    if hash == "all":  
      [x.delete() for x in SharedObject.all()]
    else:
      [x.delete() for x in SharedObject.gql("WHERE hash = :1", hash)]
    self.redirect("/")

class LearnAction(webapp.RequestHandler):
  """Learns a user.  This allows the user to use the app.
  """
  @loggedin
  @verify_xsrf_token
  def get(self):
    friend = self.request.queryvars["friend"]
    if friend:
      friends = [x.strip() for x in friend.strip().split(",")]
      for email in friends:
        friend = LearnedUsers()
        friend.invited_by = users.get_current_user()
        friend.fuzzy_email = email
        friend.put()
    self.redirect("/")

class ListPage(webapp.RequestHandler):
  @loggedin
  def get(self):
    gql = "ORDER BY date DESC"
    if not users.is_current_user_admin():
      gql = "WHERE secret = False " + gql

    self.response.headers['Content-type'] = "text/plain"
    for r in SharedObject.gql(gql):
      self.response.out.write("%s\t\n" % r.filename)

class MainPage(webapp.RequestHandler):
  """Displays the upload form and file listing.
  """
  @loggedin 
  def get(self):
    gql = "ORDER BY date DESC"
    if not users.is_current_user_admin():
      gql = "WHERE secret = False " + gql          

    # Establish the XSRF token.  This is verified by @verify_xsrf_token.
    c = Cookie.Cookie()
    c.load(self.request.headers["Cookie"])
    if not c.has_key("xt"):
      # Establish the XSRF cookie.  We use a random string of 7 characters.
      token = sha.sha(str(random.random())).hexdigest()[:7]
      self.response.headers["Set-Cookie"] = "xt=%s" % token
    else:
      token = c["xt"].value

    template_values = {      
      "you_are": users.get_current_user(),
      "user_is_god": users.is_current_user_admin(),
      "data": SharedObject.gql(gql),
      "logout_url": users.create_logout_url(self.request.uri),
      "xsrf_token": "xt" + token,
    }
    
    path = os.path.join(os.path.dirname(__file__), 'upload.html')
    self.response.out.write(template.render(path, template_values))

class InvitationOnlyPage(webapp.RequestHandler):
  def get(self):
    self.response.out.write("Sorry, you aren't invited to this party.<br/>")
    self.response.out.write("Go <a href='" + 
                            users.create_logout_url("http://omg.yahoo.com/") + 
                            "'>read tabloids</a> instead?<br/>")

class ForeverStaticFile(webapp.RequestHandler):
  """Serves a static file with HTTP headers configured so that the browser
  should cache the file for a very long time and not issue If-Modified-Since
  requests.

  Why: This is useful when you serve files that never change (such as jQuery)
  because it reduces the # of HTTP requests the browser makes.  
  """
  @cacheliberally
  def get(self, fingerprint, filename):    
    # only allow specific files to be served.
    if filename not in static_files:
      self.error(403)
      return

    path = os.path.join(os.path.dirname(__file__), filename)
    mtime = os.stat(path)[-2]
    
    if "If-Modified-Since" in self.request.headers:
      ims = self.request.headers["If-Modified-Since"]
      if ims:
        ims_time = time.strptime(ims, http_time_format)
        if ims_time >= mtime:
          self.error(304)
          return

    content_type = extensions[filename.split(".").pop()][0]
    
    self.response.headers['Content-Type'] = content_type
    self.response.headers['Cache-Control'] = "public"
    year = (datetime.datetime.utcnow() + 
            datetime.timedelta(days=365)).strftime(http_time_format)
    self.response.headers['Expires'] = year
    self.response.headers['Last-Modified'] = time.strftime(http_time_format, 
                                                           time.gmtime(mtime))            
    self.response.out.write(open(path).read())
    
def main():
  application = webapp.WSGIApplication([
    ('/', MainPage),
    ('/list', ListPage),
    ('/upload', UploadAction),
    ('/invitationonly', InvitationOnlyPage),
    ('/get/([^/]+)/([^/]+)', GetPage),
    ('/remove/([^/]+)/([^/]+)', RemoveAction),
    ('/s/([^/]+)/([^/]+)', ForeverStaticFile),
    ('/love', LearnAction),
  ], debug=True)
  wsgiref.handlers.CGIHandler().run(application)

if __name__ == "__main__":
  main()
