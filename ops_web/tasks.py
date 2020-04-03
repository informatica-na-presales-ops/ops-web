import logging

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import ops_web.aws
    import ops_web.db

log = logging.getLogger(__name__)


def update_termination_protection(aws_client: 'ops_web.aws.AWSClient', db: 'ops_web.db.Database', machine_id: str):
    machine = db.get_machine(machine_id)
    region = machine.get('region')
    tp = aws_client.get_termination_protection(region, machine_id)
    db.set_machine_termination_protection(machine_id, tp)
