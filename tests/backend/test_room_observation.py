import asyncio,json
from services.agent import room_observation as observation

class Response:
    def __init__(self,value,truncated=False):self.value=value;self.truncated=truncated;self.commands=[]
    async def execute(self,command,timeout=10):
        self.commands.append((command,timeout))
        return {'exit_code':0,'stdout':json.dumps(self.value),'capture':{'stdout_truncated':self.truncated}}

def test_bounded_metadata_sample_and_capture_failure_are_distinct():
    value={'version':observation.VERSION,'mode':'files','partial':False,
           'files':[{'path':'/work/output.json','inode':1,'size':12,'mtime_ns':1,'mode':32768}]}
    session=Response(value);result=asyncio.run(observation.sample(session,'files'))
    assert result['observation_status']=='observed' and result['file_count']==1
    assert result['snapshot']==value and session.commands[0][1]==2
    assert ' -I -S ' in session.commands[0][0]
    bad=asyncio.run(observation.sample(Response(value,True),'files'))
    assert bad['observation_status']=='unavailable' and 'file_count' not in bad
    value['partial']=True
    assert asyncio.run(observation.sample(Response(value),'files'))['observation_status']=='partial'

def test_unknown_fields_host_paths_and_unexpected_groups_are_not_accepted():
    value={'version':observation.VERSION,'mode':'files','partial':False,'files':[], 'host_secret':'private'}
    assert asyncio.run(observation.sample(Response(value),'files'))['observation_status']=='unavailable'
    value.pop('host_secret');value['files']=[{'path':'/etc/private','inode':1,'size':1,'mtime_ns':1,'mode':32768}]
    assert asyncio.run(observation.sample(Response(value),'files'))['observation_status']=='unavailable'

def test_pid_and_network_samples_are_counts_not_command_or_packet_content():
    value={'version':observation.VERSION,'mode':'all','partial':False,'files':[],
           'process_ids':[1,17],'network_socket_counts':{'tcp':0,'tcp6':0,'udp':1,'udp6':0}}
    result=asyncio.run(observation.sample(Response(value),'all'))
    assert result['process_count']==2 and result['network_socket_count']==1
    assert 'argv' not in json.dumps(result) and 'packet' not in json.dumps(result)
