from tornado.routing import Router
import tornado.web

class BaseHandler(tornado.web.RequestHandler):

    def compute_etag(self): pass

    async def prepare(self):
        raise tornado.web.Finish()

    async def block(self, status=200, reason='', headers={}, response=None, log=None):
        self.set_status(200, reason=reason)
        [self.set_header(k,v) for k,v in headers]
        self.set_header('X-Waf-Status','1')
        self.finish(response)


class WAF(Router):

    def __init__(self, *args, **kwargs):
        Router.__init__(self, *args, **kwargs)
        self._webapp = tornado.web.Application()
        self.rules = {}

    def setup(self, *args, **kwargs):
        self._webapp = tornado.web.Application(*args, **kwargs)
        return self

    def find_handler(self, request, **kwargs):
        request.motherfucker = self
        handler = self.rules.get(request.headers.get("x-waf-match-id"), BaseHandler)
        return self._webapp.get_handler_delegate(request, handler)

    def build(self, rule_id, auto_policy=None):
        def wrap(worker):
            handler = type(repr(rule_id),(BaseHandler,),dict(prepare=worker))
            self.rules[rule_id] = handler
        return wrap

    def run(self, port=None, multiprocess=None):
        import tornado.ioloop
        import tornado.httpserver
        server = tornado.httpserver.HTTPServer(self, decompress_request=False)
        server.bind(port or 4999)
        server.start()
        tornado.ioloop.IOLoop().current().start()
    
