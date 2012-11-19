from api import APIHandler

class DomainHandler(APIHandler):

    queryset = Domain.all()
    customer_field = 'customer'

    denied_fields = [ 'id', 'validated' ]

    def get(self):
        pass

    def post(self):
        pass

    def put(self):
        pass

    def delete(self):
        pass
