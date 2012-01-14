#!/usr/bin/python
"""Parse an email, digest the headers and report it to the gmail abuse url.

The URL is:
https://support.google.com/mail/bin/request.py?hl=en&contact_type=abuse

The form will require the following information:
  email-of-reporter
  gmail-username (optional)
  gmail-involved (to/reply-to)
  message headers
  message subject
  message budy
"""
import cookielib
import email
import logging
import os
import re
import sys
import urllib
import urllib2

from optparse import OptionParser

REQ_TYPE = 'https'
REQ_URL = '%s://support.google.com' % REQ_TYPE

FORM_URL = ('%s/mail/bin/request.py?hl=en&contact_type=abuse' % REQ_URL)

POST_URL = '%s/mail/bin/request.py?hl=en&ctx=submitted&confirm=abuse' % REQ_URL

USERAGENT = {'User-agent' : 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}


class Error(Exception):
  """Base Exception Class."""


class MessageReadError(Error):
  """An error class used in reporting failures to read the message."""


class ReportableMsg(object):
  """A message to process and report via the URL for gmail spam reports.

  Args:
    msg: a string, the file name of the message file (unix-mbox).
  """
  def __init__(self, msg):
    self.msg = msg
    self.obj = self.readEmail()
    self.headers = self.readHeaders()

  def readEmail(self):
    """Read an email message off disk, into an email object.

    Raises:
      MessageReadError: if the message is unreadable.
      email.errors.MessageParseError: if there is an error in parsing the
        message.
    """
    try:
      fd = open(self.msg)
    except IOError, err:
      logging.debug('Opening the msg file(%s)  failed: %s', self.msg, err)
      raise MessageReadError('Failed to open the msg file: %s', err)

    try:
      obj = email.message_from_file(fd)
    except email.errors.MessageParseError, err:
      logging.debug('Parse failure for message: %s', err)
      return

    fd.close()
    return obj

  def readHeaders(self):
    """Read a message from a file, return only the message headers.

    Returns:
      a string, the message headers only, in original order.
    """
    _HEADER_RE = re.compile(r'^([\w-]+|\s+):')
    _EOH_RE = re.compile(r'^$')
    _EXT_HEADER_RE = re.compile(r'^\s+')

    fd = open(self.msg)
    headers = []
    for line in fd:
      if _EOH_RE.match(line):
        break

      header_match = _HEADER_RE.search(line)
      extended_header_match = _EXT_HEADER_RE.search(line)
      if header_match or extended_header_match:
        if extended_header_match:
          headers[len(headers)-1] = '%s%s' % (headers[len(headers)-1], line)
        else:
          headers.append(line)

    return ''.join(headers)

  def getBody(self, payload):
    """Return the body as a single string.

    Args:
      payload: a list of email body objects.

    Returns:
      a string, the entire body.
    """
    body = []
    for el in payload:
      if type(el) == str:
        body.append(el)
      else:
        body.append(el.as_string())

    return ''.join(body)

  def getHeader(self, header):
    """Find and return a singular header item.

    Args:
      header: a string, the header to find and return.

    Returns:
      a string, the header content found.
    """
    return self.obj.get(header)

  def getPayload(self):
    """Get the payload from an email obj.
    
    Returns:
      a list, the payload from a message.
    """
    return self.obj.get_payload()


class FormRequest(object):
  """Create a URL Request, initially gather the cookies for a session."""
  def __init__(self, starturl):
    self.starturl = starturl
    self.jar = cookielib.CookieJar()
    self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.jar))
    urllib2.install_opener(self.opener)

  def getCookie(self):
    """Initiate an opener, fill it's jar."""
    req = urllib2.Request(self.starturl)
    req.add_header('User-agent', USERAGENT['User-agent'])
    try:
      result = self.opener.open(req)
    except urllib2.HTTPError, err:
      print 'Failed to open and get a cookie: %s' % err
      return None
    return len(result.read())

  def getForm(self, post_url, data):
    """Post the form content."""
    req = urllib2.Request(post_url, data)
    req.add_header('User-agent', USERAGENT['User-agent'])
    try:
      result = self.opener.open(req)
    except urllib2.HTTPError, err:
      print 'Failed to post the URL properly: %s' % err
      return None
    
    return result


def main():
  """Gather options, process content, return success/failure."""
  opts = OptionParser()

  # Requred
  opts.add_option('-b', '--browser', dest='browser',
                  default='Firefox',
                  help='What browser name should be used in the report.')

  # Required
  opts.add_option('-e', '--email', dest='email',
                  default='',
                  help='An Email address to use as a contact address.')

  # Optional
  opts.add_option('-g', '--gmail', dest='gmail',
                  default='',
                  help='An OPTIONAL gmail account for contact.')

  # Optional
  opts.add_option('-i', '--impersonating', dest='impersonating',
                  action='store_true', default=None,
                  help='Is the email impersonating google?')

  # Required
  opts.add_option('-m', '--msg', dest='msg',
                  default='',
                  help='Email message file to process.')

  # Required
  opts.add_option('-o', '--os', dest='AutoDetectedOs',
                  default='Linux',
                  help='Fill in the OptionalOS detected value in the form.')

  (options, unused_args) = opts.parse_args()

  if not os.path.exists(options.msg):
    logging.debug('Failed to find the msg file: %s', options.msg)
    print 'Failed to find the email to report (no file)'
    sys.exit(255)

  if not options.email:
    logging.debug('No specified contact email account.')
    print 'No specified email account.'
    sys.exit(255)

  emailobj = ReportableMsg(options.msg)
  headers = emailobj.headers
  subject = emailobj.getHeader('Subject')
  # TODO(morrowc): This may only catch the From: not the ReplyTo:
  #                Should try both and prefer (?) ReplyTo:.
  sender = emailobj.getHeader('From')
  body = emailobj.getBody(emailobj.getPayload())
  
  # Now, create a urllib request to the URI.
  postdata = {'extra.IssueType': 'abuse',
              'extra.Language': 'en',
              'extra.IIILanguage': 'en',
              'extra.AutoDetectedBrowser': options.browser,
              'extra.AutoDetectedOS': options.AutoDetectedOs,
              'email': options.email,
              'extra.03_abuser_gmail': sender,
              'extra.04_orig_subject': subject,
              'extra.05_headers': headers,
              'extra.06_content':  body,
              'submit_abuse': True,
             }

  if options.impersonating:
    postdata['extra.02_impersonating_google_yes'] = True

  if options.gmail:
    postdata['extra.01_reporter_gmail'] = options.gmail

  requestor = FormRequest(FORM_URL)
  if requestor.getCookie():
    result = requestor.getForm(POST_URL, urllib.urlencode(postdata))
  else:
    print 'Faild to get a cookie?'
    sys.exit(1)

  if result.getcode() == 200:
    if 'Thank you for submitting a report' in  ''.join(result.readlines()):
      print 'Successfully reported.'
    else:
      print 'Submit succeeded, there was a problem with the data entered.'
  else:
    print 'FAILED'


if __name__ == '__main__':
  main()

