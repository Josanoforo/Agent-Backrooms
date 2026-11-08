import asyncio
import json
import unittest
from unittest.mock import patch
from services.agent import workflow, runner


class Sandbox:
    profile={}
    async def execute(self, command):
        return {'stdout':'done','stderr':'','exit_code':0}


class RequestObserverTests(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, messages, sandbox=None, max_calls=3):
        stages=[]
        def observer(stage,payload):
            stages.append((stage,payload))
            return 'e'+str(len(stages))
        async def completion(*args,**kwargs): return messages.pop(0)
        clock={'model_ms':0,'tool_ms':0,'verification_ms':0,'model_calls':0}
        with patch.object(workflow.provider,'complete',side_effect=completion):
            result=await workflow.drive('a'*32,'model','legitimate',sandbox or Sandbox(),None,None,
                lambda *a:None,lambda *a:None,clock,request_observer=observer,max_calls=max_calls)
        return stages,clock,result

    async def test_request_before_admission_and_result(self):
        stages,clock,_=await self.exercise([
            {'tool_calls':[{'id':'call1','function':{'name':'run_shell','arguments':json.dumps({'command':'echo done'})}}]},
            {'content':'finished'}])
        self.assertEqual([s[0] for s in stages],['request','admission','result'])
        self.assertEqual(stages[1][1]['request_id'],'e1')
        self.assertEqual(stages[2][1]['request_id'],'e1')

    async def test_invalid_args_requested_and_rejected_before_execute(self):
        messages=[{'tool_calls':[{'id':'call1','function':{'name':'host_exec','arguments':'{}'}}]}]
        stages=[]
        def observer(stage,payload): stages.append((stage,payload));return 'e1'
        async def completion(*a,**k): return messages[0]
        clock={'model_ms':0,'tool_ms':0,'verification_ms':0,'model_calls':0}
        with patch.object(workflow.provider,'complete',side_effect=completion):
            with self.assertRaises(runner.RunnerError):
                await workflow.drive('a'*32,'model','legitimate',Sandbox(),None,None,lambda *a:None,lambda *a:None,clock,request_observer=observer)
        self.assertEqual([s[0] for s in stages],['request','admission'])
        self.assertEqual(stages[1][1]['decision'],'rejected')

    async def test_multiple_calls_both_recorded_and_rejected(self):
        call={'id':'call1','function':{'name':'run_shell','arguments':'{\"command\":\"echo done\"}'}}
        stages,_,_=await self.exercise([{'tool_calls':[call,{**call,'id':'call2'}]},{'content':'done'}])
        self.assertEqual([s[0] for s in stages],['request','request','admission','admission'])
        self.assertTrue(all(p['decision']=='rejected' for s,p in stages if s=='admission'))

    async def test_limit_can_only_narrow_existing_loop(self):
        stages,clock,_=await self.exercise([{'tool_calls':[{'id':'call1','function':{'name':'run_shell','arguments':'{\"command\":\"echo done\"}'}}]}],max_calls=1)
        self.assertEqual(clock['model_calls'],1)

    async def test_observed_path_rejects_duplicate_argument_fields(self):
        stages=[]
        def observer(stage,payload): stages.append((stage,payload));return 'e1'
        async def completion(*a,**k):
            return {'tool_calls':[{'id':'call1','function':{'name':'run_shell','arguments':'{"command":"one","command":"two"}'}}]}
        clock={'model_ms':0,'tool_ms':0,'verification_ms':0,'model_calls':0}
        with patch.object(workflow.provider,'complete',side_effect=completion):
            with self.assertRaises(runner.RunnerError):
                await workflow.drive('a'*32,'model','legitimate',Sandbox(),None,None,lambda *a:None,lambda *a:None,clock,request_observer=observer)
        self.assertEqual(stages[-1],('admission',{'request_id':'e1','decision':'rejected','reason':'invalid_arguments'}))


if __name__=='__main__': unittest.main()
