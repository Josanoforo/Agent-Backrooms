"""Host-operator control, never mounted in either room or accepted via MCP args."""
import json
from pathlib import Path
import time
import uuid


class CatalogControl:
    def __init__(self, folder):
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)

    def status(self, run_id, *, closed, lifetime, admitted=False):
        # A fixed, operator-selected directory; the agent cannot choose a path.
        value = {'schema': 'external-operator-session/v1', 'run_id': run_id,
                 'closed': closed, 'admitted': admitted, 'lifetime_seconds': lifetime}
        if admitted:
            previous = self._read('operator-session.json')
            value['expires_at_epoch'] = (previous.get('expires_at_epoch')
                if previous.get('run_id') == run_id and previous.get('admitted')
                else time.time() + lifetime)
        target = self.folder / 'operator-session.json'
        temp = target.with_suffix('.tmp')
        temp.write_text(json.dumps(value), encoding='utf-8')
        temp.replace(target)

    def _read(self, name):
        try:
            with (self.folder / name).open('rb') as stream:
                raw = stream.read(2049)
            if len(raw) > 2048: return {}
            value = json.loads(raw)
            return value if type(value) is dict else {}
        except (OSError, ValueError):
            return {}

    GRANT_ORIGINS = ('operator_live', 'operator_pre_authorized_in_plan')

    def granted(self, run_id):
        value = self._read('catalog-authorization.json')
        keys = set(value)
        if 'origin' in keys:  # optional declared provenance; any other extra key still fails closed
            if value.get('origin') not in self.GRANT_ORIGINS: return False
            keys.discard('origin')
        return (keys == {'schema', 'run_id', 'catalog_read'}
                and value.get('schema') == 'external-catalog-grant/v1'
                and value.get('run_id') == run_id and value.get('catalog_read') is True)

    def grant_origin(self, run_id):
        value = self._read('catalog-authorization.json')
        return value.get('origin', 'operator_live') if self.granted(run_id) else None

    def recovery_status(self, run_id, status, details=None):
        """Record operator reconciliation separately from the expiring session/grant."""
        value = {'schema': 'external-recovery/v1', 'run_id': run_id,
                 'status': status, 'details': details or {}}
        target = self.folder / ('recovery-' + run_id + '.json')
        temp = target.with_name(target.name + '.' + uuid.uuid4().hex + '.tmp')
        temp.write_text(json.dumps(value, sort_keys=True), encoding='utf-8')
        temp.replace(target)

    def invalidate_recovered_grant(self, run_id):
        """Remove only this session's exact grant; never touch another run's authorization."""
        grant = self._read('catalog-authorization.json')
        if grant.get('schema') == 'external-catalog-grant/v1' and grant.get('run_id') == run_id:
            (self.folder / 'catalog-authorization.json').unlink()
            return True
        return False
