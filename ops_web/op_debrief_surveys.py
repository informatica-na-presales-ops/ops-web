import datetime
import flask
import logging
import ops_web.config
import ops_web.db
import ops_web.send_email
import werkzeug.datastructures

from typing import Dict

log = logging.getLogger(__name__)


def generate_op_debrief_surveys(config: ops_web.config.Config, app: flask.Flask):
    log.info('Generating opportunity debrief surveys')
    now = datetime.datetime.utcnow()
    db = ops_web.db.Database(config)
    last_check = db.get_last_op_debrief_check()
    log.info(f'Looking for opportunities modified after {last_check}')
    modified_ops = db.get_modified_opportunities(last_check)
    existing_survey_op_numbers = db.get_op_numbers_for_existing_surveys()
    selected_roles = [r.get('role_name') for r in db.get_roles() if r.get('generate_survey')]
    for op in modified_ops:
        op_number = op.get('opportunity_number')
        if op_number in existing_survey_op_numbers:
            log.debug(f'Already sent surveys for {op_number}')
            continue
        log.info(f'Generating surveys for {op_number}')
        team_members = db.get_op_team_members(op.get('opportunity_key'))
        for t in team_members:
            email = t.get('email')
            role = t.get('role')
            if role in selected_roles:
                survey_id = db.add_survey(op_number, email, t.get('role'))
                c = {
                    'opportunity': op,
                    'person': t,
                    'survey_id': survey_id
                }
                with app.app_context():
                    body = flask.render_template('op-debrief/survey-email.html', c=c)
                ops_web.send_email.send_email(config, email, 'Opportunity debrief survey', body)
            else:
                log.debug(f'Skipping {email} because role {role!r} is not selected')
    log.info('Done generating opportunity debrief surveys')
    db.update_op_debrief_tracking(now)


survey_template = {
    'plr_options': {
        'price': 'Price',
        'key-decision-maker-left': 'Key decision maker left',
        'project-cancelled': 'Project cancelled or delayed',
        'competitive-loss-tech': 'Competitive loss (technology gap)',
        'competitive-loss-other': 'Competitive loss (other)',
    },
    'tech_gap_categories': {
        'runtime': 'Runtime',
        'design_time': 'Design-time',
        'connectivity': 'Connectivity',
        'install': 'Install',
    },
    'tech_gap_options': {
        'performance': 'Performance',
        'stability': 'Stability',
        'missing_features': 'Missing features',
        'compatibility': 'Compatibility',
        'ease_of_use': 'Ease of use',
    },
    'who_engaged_options': {
        'engaged_other_specialists': 'Other specialists',
        'engaged_gcs': 'Global Customer Support',
        'engaged_pm': 'Product Management',
        'engaged_dev': 'Development',
    },
    'validation_activities': {
        'did_rfp': 'RFP',
        'did_standard_demo': 'Standard demo',
        'did_custom_demo': 'Custom demo',
        'did_eval_trial': 'Evaluation / Trial',
        'did_poc': 'POC',
    },
    'poc_outcomes': {
        'tech-win': 'Secured technical win',
        'no-tech-win': 'Did not secure technical win',
        'no-outcome': 'No clear outcome',
        'partner-tech-win': 'Partner led, technical win',
        'partner-no-tech-win': 'Partner led, no technical win',
        'not-sure': 'Not sure',
    },
    'poc_failure_reasons': {
        'success-criteria': 'Undefined or poorly-defined success criteria',
        'use-cases': 'Undefined or poorly-defined use cases',
        'customer-not-engaged': 'Customer not engaged',
        'tech-gap': 'Technology gap',
    }
}


def convert_form_to_record(form: werkzeug.datastructures.ImmutableMultiDict) -> Dict:
    record = {
        'close_contacts': ' '.join(form.getlist('close-contacts')),
        'poc_failure_reason': form.get('poc-failure-reason'),
        'poc_outcome': form.get('poc-outcome'),
        'primary_loss_reason': form.get('primary-loss-reason')
    }

    tech_gap_type = form.getlist('tech-gap-type')
    for cat in survey_template.get('tech_gap_categories'):
        for opt in survey_template.get('tech_gap_options'):
            record[f'tg_{cat}_{opt}'] = f'tg-{cat}-{opt}' in tech_gap_type

    who_engaged = form.getlist('who-engaged')
    for opt in survey_template.get('who_engaged_options'):
        record[opt] = opt in who_engaged

    validation_activities = form.getlist('validation-activities')
    for opt in survey_template.get('validation_activities'):
        record[opt] = opt in validation_activities

    return record
