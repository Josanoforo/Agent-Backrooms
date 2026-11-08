import asyncio
import json
from types import SimpleNamespace

from services.agent.external_bridge import Bridge
from tests.backend.test_external_room_routes import Store,Session


def test_transition_is_denied_without_operator_route():
    async def check():
        bridge=Bridge(Store(),'task',level='processes',local_docker=True,session_factory=Session)
        bridge.initialize({'clientInfo':{}});bridge.initialized=True
        reply=await bridge.call('room_enter',{'destination':'network'})
        assert json.loads(reply['content'][0]['text'])['reason']=='room_transition_not_authorized'
        assert bridge.session is None
    asyncio.run(check())


def test_same_run_fresh_room_receives_only_verified_artifact():
    async def check():
        store=Store();bridge=Bridge(store,'task',journey='workflow,processes',local_docker=True,session_factory=Session)
        run=bridge.run_id;old=Session();bridge.session=old;bridge.task_prepared=True
        artifact={'accepted_ids':['A','B'],'duplicate_ids':[],'mismatches':[],'accepted_total_cents':71}
        async def finish(session):return {'task':{'status':'passed','reason':'result_matches'}}
        bridge.room_task=SimpleNamespace(finish=finish,material=SimpleNamespace(mission=SimpleNamespace(expected=artifact)))
        answer=await bridge.enter_next_room('e1')
        assert answer['transition']=='completed' and bridge.run_id==run and bridge.level=='processes'
        assert old.cleanup_confirmed and bridge.session is not old
        data=json.loads(bridge.session.input)
        assert data=={'n':80,'n_rule':'40 * len(previous_verified_result.accepted_ids)','previous_verified_result':artifact}
        kinds=[kind for kind,_ in store.events]
        assert kinds.index('cleanup')<kinds.index('resource_pending')<kinds.index('resource_open')<kinds.index('room_transition')
        transition=store.events[-1][1]
        assert transition['run_id_unchanged'] and transition['old_cleanup_confirmed']
        await bridge.session.close()
    asyncio.run(check())


def test_failed_previous_task_cannot_advance_or_copy_result():
    async def check():
        bridge=Bridge(Store(),'task',journey='workflow,processes',local_docker=True,session_factory=Session)
        old=Session();bridge.session=old;bridge.task_prepared=True
        async def finish(session):return {'task':{'status':'failed','reason':'result_differs'}}
        bridge.room_task=SimpleNamespace(finish=finish)
        answer=await bridge.enter_next_room('e1')
        assert answer['transition']=='denied' and bridge.session is old and not old.cleanup_confirmed
        await old.close()
    asyncio.run(check())
