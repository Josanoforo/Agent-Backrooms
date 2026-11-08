"""F1 of independent M5 review: bounded raw observation precedes sanitization."""
import asyncio
import json
import pytest
from test_actor_network_adapters import directory, options, resources, active, state, runner

@pytest.mark.parametrize('mode',['exit125','exit126','exit127','boundary'])
def test_positive_nonce_is_observed_before_reserved_exit_whitening_or_visible_boundary(directory,mode):
    with state.open_actor_inventory(directory,**options(),initialize=True) as store:
        owner,adapter=resources(store);intent=active(store,adapter,owner)
        token=adapter._cache[intent.intent_id]['token'];original=owner._execute
        async def execute(observed,args,**kwargs):
            if args[0]=='sh':
                text=('x'*8180 if mode=='boundary' else '')+token
                # The runner captures bytes up to the requested bound, exactly the reviewed costure.
                captured=text.encode()[:kwargs['output_limit']].decode()
                return dict(stdout=captured,stderr='',exit_code=0 if mode=='boundary' else int(mode[4:]),**runner.unavailable_measurement())
            return await original(observed,args,**kwargs)
        owner._execute=execute
        result=asyncio.run(adapter.action(intent,'instrument'))
        assert result['model_nonce_seen'] is True
        assert token not in json.dumps(result) and token[:12] not in result['result']['stdout']
        if mode!='boundary':assert result['result']['stdout']==result['result']['stderr']==''
