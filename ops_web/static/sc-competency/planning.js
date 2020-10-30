// do all this when the employee selection changes
document.getElementById('select-sc').addEventListener('change', function () {
    const selected_option = this.options[this.selectedIndex];
    const employee_id = selected_option.value;

    // enable the save button
    document.querySelectorAll('button').forEach(function (el) {
        el.disabled = false;
    });

    // show last score timestamp block
    document.getElementById('last-score').classList.remove('show');
    if (selected_option.dataset.scoreTimestamp) {
        document.getElementById('last-score-span').textContent = selected_option.dataset.scoreTimestamp;
        document.getElementById('last-score').classList.add('show');
    }

    // show job title
    document.getElementById('job-title-span').textContent = selected_option.dataset.jobTitle;
    document.getElementById('job-title').classList.add('show');

    // get the expected score
    let expected_score = parseInt(selected_option.dataset.expectedScore);
    if (isNaN(expected_score)) {
        expected_score = 1;
    }

    // hide all content columns
    document.querySelectorAll('.score-column').forEach(function (el) {
        el.classList.remove('show');
    });

    // clear current score badges
    document.querySelectorAll('.current-score').forEach(function (el) {
        el.textContent = '';
        el.classList.remove('badge-danger', 'badge-light', 'badge-success');
    });

    // clear plan text
    document.querySelectorAll('textarea').forEach(function (el) {
        el.value = '';
    })

    const competency_ids = [
        'technical-acumen',
        'domain-knowledge',
        'discovery-and-qualification',
        'teamwork-and-collaboration',
        'leadership-skills',
        'communication',
        'planning-and-prioritization',
        'customer-advocacy',
        'attitude',
        'corporate-citizenship'
    ];

    // set current score badges and show content columns
    for (const id of competency_ids) {
        let current_score = parseInt(selected_option.getAttribute(`data-${id}`));
        if (isNaN(current_score)) {
            // do nothing
        } else {
            const badge = document.getElementById(`badge-${id}-current`);
            badge.textContent = current_score.toString();
            if (current_score > expected_score) {
                badge.classList.add('badge-success');
            } else if (current_score < expected_score) {
                badge.classList.add('badge-danger');
            } else {
                badge.classList.add('badge-light');
            }
        }
        let left_column = current_score;
        if (isNaN(left_column)) {
            left_column = expected_score;
        }
        if (left_column > 4) {
            left_column = 4;
        } else if (left_column < 1) {
            left_column = 1;
        }
        let right_column = left_column + 1;
        document.getElementById(`${id}-${left_column}`).classList.add('show');
        document.getElementById(`${id}-${right_column}`).classList.add('show');

        // put plan text in textarea
        document.getElementById(`${id}-plan`).value = document.getElementById(`${employee_id}-plan`).getAttribute(`data-${id}`);
    }
});
