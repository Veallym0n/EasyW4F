import easywaf
import tornado.web
waf = easywaf.WAF()

@waf.build(rule_id='test123')
async def test(req):
    await req.block()

waf.run(port=80)
