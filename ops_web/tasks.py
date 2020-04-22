import concurrent.futures
import datetime
import logging
import ops_web.aws
import ops_web.db

log = logging.getLogger(__name__)


def update_termination_protection(db: ops_web.db.Database):
    log.info('Checking termination protection for all AWS machines')
    sync_start = datetime.datetime.utcnow()

    def _update_one_machine(_aws: ops_web.aws.AWSClient, _db: ops_web.db.Database, _region: str, _machine_id: str):
        tp = _aws.get_termination_protection(_region, _machine_id)
        _db.set_machine_termination_protection(_machine_id, tp)

    aws_clients = {}
    with concurrent.futures.ThreadPoolExecutor() as ex:
        fs = []
        for machine in db.get_all_visible_machines():
            if machine.get('cloud') == 'aws':
                machine_id = machine.get('id')
                account_id = machine.get('account_id')
                if account_id in aws_clients:
                    aws = aws_clients.get(account_id)
                else:
                    cred = db.get_one_credential_for_use(account_id)
                    aws = ops_web.aws.AWSClient(db.config, cred.get('username'), cred.get('password'))
                    aws_clients[account_id] = aws
                fs.append(ex.submit(_update_one_machine, aws, db, machine.get('region'), machine_id))
        concurrent.futures.wait(fs)
    sync_duration = datetime.datetime.utcnow() - sync_start
    log.info(f'Done checking termination protection for all AWS machines / {sync_duration}')
