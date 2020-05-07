import datetime
import flask
import logging
import ops_web.config
import ops_web.db
import ops_web.send_email

log = logging.getLogger(__name__)


def generate_op_debrief_surveys(config: ops_web.config.Config, app: flask.Flask):
    log.info('Generating opportunity debrief surveys')
    now = datetime.datetime.utcnow()
    db = ops_web.db.Database(config)
    last_check = db.get_last_op_debrief_check()
    log.info(f'Looking for opportunities modified after {last_check}')
    modified_ops = db.get_modified_opportunities(last_check)
    existing_survey_op_numbers = db.get_op_numbers_for_existing_surveys()
    for op in modified_ops:
        op_number = op.get('opportunity_number')
        if op_number in existing_survey_op_numbers:
            log.debug(f'Already sent surveys for {op_number}')
            continue
        log.info(f'Generating surveys for {op_number}')
        team_members = db.get_op_team_members(op.get('opportunity_key'))
        for t in team_members:
            email = t.get('email')
            survey_id = db.add_survey(op_number, email, t.get('role'))
            c = {
                'opportunity': op,
                'person': t,
                'survey_id': survey_id
            }
            with app.app_context():
                body = flask.render_template('op-debrief-survey-email.html', c=c)
            ops_web.send_email.send_email(config, email, 'Opportunity debrief survey', body)
    log.info('Done generating opportunity debrief surveys')
    db.update_op_debrief_tracking(now)
