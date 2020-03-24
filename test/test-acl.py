# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

from init import provider 

rules = [
	'x@x.com can access rs1.com/x/y/z/t/a/b/c for 2 days',
	'x@x.com can access rs1.com/_x/y/z/t/a/b/c for 2 days if country = "IN" AND api = "/latest"',
	'x@x.com can access rs1.com/x-t/y/z/t/a/b/c for 2 days if country = "IN" OR  api = "/latest"',
	'consumer1@domain.com and consumer2@domain.com can access rs1.com/x for 5 hours @ 5 INR',
	'a,b@b.com, and c can access x/y/z.a.b.c/t for 2 seconds @ 10.5 INR; all can access anything; x can access y',
]

for rule in rules:
	r = provider.set_policy(rule)
	assert r['success'] is True 
