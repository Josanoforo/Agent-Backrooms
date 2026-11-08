"""Verify the new exploratory mode, not a rerun of known room defects."""
import asyncio,json,sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).parent))
from test_actor_rooms_backend import RoomCase
from services.agent import guards,budget,room_agent


class TestOwnerShell(RoomCase):
    async def test_default_policy_and_opt_in_limit_preserve_owner_boundary(self):
        opened=await self.opened_level(level='processes')
        request={'op':'execute','handle':opened['handle'],'command':'printf chosen'}
        self.assertEqual((await self.call(request))['reason'],'wrong_domain')
        await self.close_handle(opened['handle'])
        self.reset(allowed_shell_levels=('processes',))
        opened=await self.opened_level(run='b'*32,level='processes');request['handle']=opened['handle']
        for index in range(12):
            answer=await self.call(request)
            self.assertTrue(answer['ok'],(index,answer,self.log))
        self.assertEqual((await self.call(request))['reason'],'action_consumed')
        self.assertEqual(self.runtime.calls['execute'],12)
        self.assertTrue((await self.close_handle(opened['handle']))['cleanup_confirmed'])

    async def test_unlisted_level_cannot_gain_shell_authority(self):
        with self.assertRaises(ValueError):self.make(allowed_levels=('memory',),allowed_shell_levels=('memory',))


def test_exploratory_reservations_are_per_dispatch_and_bounded(tmp_path,monkeypatch):
    path=tmp_path/'budget.sqlite3';today=guards.day()
    for k,v in {'ESCAPE_D2B_AUTHORIZED_DAY_UTC':today,'ESCAPE_D2B_REQUIRE_AUTHORIZED_DAY':'1','ESCAPE_DAILY_USD_LIMIT':'0.5','ESCAPE_MAX_CALLS':'100','ESCAPE_MAX_RUNS':'10','ESCAPE_MAX_OUTPUT_TOKENS':'102400','ESCAPE_USAGE_RATE_JSON':json.dumps({'model':'glm-5.3-flash','effective_date':today,'input_per_million':.1,'output_per_million':.35})}.items():monkeypatch.setenv(k,v)
    with guards.room_authorization(today,str(path),exploratory=True) as context:
        for _ in range(8):guards.reserve(str(path),'glm-5.3-flash',[{'role':'user','content':'goal'}],room=context)
        assert context.reserved_calls==8 and budget.read_counters(path)['calls']==8
        with pytest.raises(guards.GuardError):guards.reserve(str(path),'glm-5.3-flash',[],room=context)
    assert budget.read_counters(path)['calls']==8
