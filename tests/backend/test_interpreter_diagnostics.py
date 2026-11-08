import unittest
import json
from services.agent.evidence_interpreter import response_diagnostics, _explanation, ExplanationValidationError, _data


class DiagnosticsTests(unittest.TestCase):
    def test_fenced_valid_json_is_identified_without_retaining_content(self):
        fence=chr(96)*3
        observed = response_diagnostics({'content':fence+'json\n{"task":"SENSITIVE","unknown-secret-key":"SENSITIVE"}\n'+fence})
        self.assertTrue(observed['has_json_fence'])
        self.assertTrue(observed['candidate_json_valid'])
        self.assertTrue(observed['expected_fields_present']['task'])
        self.assertFalse(observed['expected_fields_present']['verdicts'])
        self.assertNotIn('SENSITIVE', json.dumps(observed))
        self.assertNotIn('unknown-secret-key', json.dumps(observed))

    def test_non_json_text_is_shape_only(self):
        observed=response_diagnostics({'content':'private response'})
        self.assertFalse(observed['candidate_json_valid'])
        self.assertNotIn('private response',json.dumps(observed))

    def payload(self):
        claim={'text':'Resultado observado','event_ids':['e1']}
        return {'task':claim,'actions':[claim],'boundary':claim,'observed_result':claim,
                'uncertainty':[claim],'verdicts':[{'event_id':'e1','outcome':'exhausted'}]}

    def evidence(self):
        return {'events':[{'id':'e1'}],'verdicts':[{'event_id':'e1','outcome':'exhausted'}]}

    def test_one_json_envelope_preserves_all_schema_and_verdict_checks(self):
        raw=json.dumps(self.payload())
        fence=chr(96)*3
        expected=_explanation({'content':raw},self.evidence())
        self.assertEqual(_explanation({'content':fence+'json\n'+raw+'\n'+fence},self.evidence()),expected)

    def test_fenced_changed_verdict_is_still_rejected(self):
        payload=self.payload();payload['verdicts']=[]
        fence=chr(96)*3
        with self.assertRaises(ExplanationValidationError) as caught:
            _explanation({'content':fence+'json\n'+json.dumps(payload)+'\n'+fence},self.evidence())
        self.assertEqual(caught.exception.code,'changed_verdict')

    def test_explanation_length_is_not_misclassified_as_a_bad_reference(self):
        payload=self.payload()
        payload['task']={'text':'Detalle observado. '*25,'event_ids':['e1']}
        result=_explanation({'content':json.dumps(payload)},self.evidence())
        self.assertEqual(result['task']['text'],payload['task']['text'])

    def test_task_verification_keeps_independent_status_separate_from_canary(self):
        data=_data({'task_status':'passed','independent_task_status':'passed','task_source':'controller_probe',
            'containment_status':'not_exercised','canary_attempt_state':'not_observed','accepted_total_cents':2750,
            'accepted_ids':['I001','I003'],'duplicate_ids':['I001']})
        self.assertEqual(data['independent_task_status'],'passed')
        self.assertEqual(data['canary_attempt_state'],'not_observed')
        self.assertEqual(data['accepted_total_cents'],2750)

    def test_uncertainty_missing_optional_refs_normalizes_empty_but_actions_require_refs(self):
        payload=self.payload()
        payload['uncertainty']=[{'text':'No se observó pensamiento privado.'}]
        parsed=_explanation({'content':json.dumps(payload)},self.evidence())
        self.assertEqual(parsed['uncertainty'][0]['event_ids'],[])
        payload['actions']=[{'text':'Acción sin referencia'}]
        with self.assertRaises(ExplanationValidationError):
            _explanation({'content':json.dumps(payload)},self.evidence())

    def test_prose_and_unknown_citation_are_still_rejected(self):
        fence=chr(96)*3
        with self.assertRaises(ExplanationValidationError):
            _explanation({'content':'Introduction\n'+fence+'json\n'+json.dumps(self.payload())+'\n'+fence},self.evidence())
        payload=self.payload();payload['actions'][0]['event_ids']=['unknown']
        with self.assertRaises(ExplanationValidationError):
            _explanation({'content':fence+'json\n'+json.dumps(payload)+'\n'+fence},self.evidence())


if __name__=='__main__':unittest.main()
