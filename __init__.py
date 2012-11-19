import webapp2
import conf
import json

import hashlib
import datetime
import time 

from models import Api
from google.appengine.ext.db import Key


from Crypto.Hash import HMAC
from Crypto.Hash import SHA


from google.appengine.api import users 
from google.appengine.ext import db 

from django.utils import simplejson  


class Auth:

    @classmethod
    def sign(cls, method, c_type, body, uri, key=None):
        sign = "%s\n%s\n%s\n%s\n%s\n" % (method, c_type, \
                                         hashlib.md5(body).hexdigest(), \
                                         datetime.datetime.utcnow()\
                                            .strftime('%Y-%m-%d-%H:%M'), uri)
        return cls.crypt(sign, key)

    @classmethod
    def crypt(cls, value, key):
        return HMAC.new(key, value, SHA).hexdigest()


class ModelEncoder(simplejson.JSONEncoder): 

    """Extends JSONEncoder to add support for GQL results and properties. 

    Adds support to simplejson JSONEncoders for GQL results and properties by 
    overriding JSONEncoder's default method. 
    """ 

    # TODO Improve coverage for all of App Engine's Property types. 

    def default(self, obj): 

        """Tests the input object, obj, to encode as JSON.""" 

        if hasattr(obj, '__json__'): 
            return getattr(obj, '__json__')() 

        if isinstance(obj, db.GqlQuery): 
            return list(obj) 

        elif isinstance(obj, db.Model): 
            properties = obj.properties().items() 
            output = {} 
            for field, value in properties: 
                output[field] = getattr(obj, field) 
            return output 

        elif isinstance(obj, datetime.datetime): 
            output = {} 
            fields = ['day', 'hour', 'microsecond', 'minute', 'month', 'second', 'year'] 
            methods = ['ctime', 'isocalendar', 'isoformat', 'isoweekday', 'timetuple'] 
            for field in fields: 
                output[field] = getattr(obj, field) 
            for method in methods: 
                output[method] = getattr(obj, method)() 
            output['epoch'] = time.mktime(obj.timetuple()) 
            return output

        elif isinstance(obj, datetime.date): 
            output = {} 
            fields = ['year', 'month', 'day'] 
            methods = ['ctime', 'isocalendar', 'isoformat', 'isoweekday', 'timetuple'] 
            for field in fields: 
                output[field] = getattr(obj, field) 
            for method in methods: 
                output[method] = getattr(obj, method)() 
            output['epoch'] = time.mktime(obj.timetuple()) 
            return output 

        elif isinstance(obj, time.struct_time): 
            return list(obj) 

        elif isinstance(obj, users.User): 
            output = {} 
            methods = ['nickname', 'email', 'auth_domain'] 
            for method in methods: 
                output[method] = getattr(obj, method)() 
            return output 

        return simplejson.JSONEncoder.default(self, obj) 


class NotFoundObject(Exception): 
    pass


class APIHandler(webapp2.RequestHandler):

    required_headers = ( 'X-API-Client', 'X-API-Request-Sign' )
    destructive_methods = ( 'PUT', 'POST', 'DELETE' )

    encoder = ModelEncoder()

    def __init__(self, request, response):
        self.initialize(request, response)

    def raise_status(self, reason, status=500):
        status = self.response.set_status(status)
        return self.render_json({'status': status, 'reason': reason})

    def sign(self):
        """
            Sign the HTTP request and validate 
        """
        return Auth.sign(self.request.method,
                         self.request.content_type,
                         self.request.body,
                         self.request.uri,
                         key=str(self.api.key()))

    def validate(self):
        """
           Validate the API headers
        """
        for header in self.required_headers:
            if header not in self.request.headers:
                return self.raise_status("Not found header %s on request" % header, status=403)

        api = Api.all().filter("client_id =",
                               self.request.headers['X-API-Client']).get()
        if not api:
            raise Exception("Specified X-API-Client not found")            

        self.api = api

        if self.sign() != self.request.headers['X-API-Request-Sign']:
            raise Exception("Invalid request signature")
        pass

    def hydrate(self):
        """
         Fill the self.request.data with the posted body data
        """
        if self.request.method in self.destructive_methods and self.request.content_type == 'application/json':
            try:
                self.request.data = json.loads(self.request.body)
            except:
                pass

    @property
    def query(self):
        if hasattr(self, 'queryset'):
            self._query = self.queryset.filter("%s =" % self.customer_field,
                                               self.api.customer)
            return self._query
        return None

    def _key_from_string(self, string):
        return Key(encoded=string)

    @property
    def object(self):
        if self.request.method in self.destructive_methods:
            if 'id' in self.request.data:
                object_id = self.request.data['id']
        else:
            object_id = self.request.get('id', None)
        try:
            self._object = self.query.filter("__key__",
                                   Key(encoded=object_id)).get()    
            if not self._object:
                raise Exception()
        except:
            raise NotFoundObject()

        return self._object

    def delete_object(self, callback):
        try:
            self.object.delete()
        except:
            return self.raise_status(
                'Cannot delete specified object', status=500)
        return self.send_json(self.object)

    def get_object(self, callback):
        get_all = self.request.get('all', False)

        if not get_all:
            try:
                if self.object:
                    return self.render_json(self.object)
            except NotFoundObject:
                return self.raise_status("Not found specified object", status=404)

        order_by = self.request.get('order_by', None)

        if order_by:
            self.query.order(order_by)

        limit = self.request.get('limit', None)

        if limit:
           limit = int(limit)

        results = self.query.fetch(limit)
        
        return self.render_json(results)

    def put_object(self, callback):
        """
           Update the given object
        """
        if hasattr(self, 'denied_fields'):
            ( denied ) = self.denied_fields

        try:
            obj_to_update = self.object
        except:
            return self.raise_status("Not found specified object", status=404)

        if not 'attributes' in self.request.data:
            return self.raise_status("Not defined attributes to update", status=500)

        for attribute, value in self.request.data['attributes'].items():
            if attribute in denied:
                return self.raise_status("Cannot update attribute %s on entity" % attribute, status=409)

            if hasattr(obj_to_update, attribute):
                setattr(obj_to_update, attribute, value)
        try:
            obj_to_update.put()
        except:
            return self.raise_status("Cannot update entity", status=500)

        return self.render_json(self.object)

    def do_the_inception(self, callback):
        method = '%s_object' % self.request.method.lower()
        if hasattr(self, method):
            return getattr(self, method)(callback)

    def dispatch(self):
        try:
            self.validate()
        except Exception as ex:
            return self.raise_status('Cannot validate request',
                                     status=403)
        #give some water to the request and let it grow
        self.hydrate()

        #map a handler to a specific request
        self.do_the_inception(webapp2.RequestHandler.dispatch)
        return webapp2.RequestHandler.dispatch(self)

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_json(self, data, header='application/json'):
        self.response.headers['Content-Type'] = header
        return self.write(self.encoder.encode(data))
