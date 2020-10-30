window.found_invalid = false;
window.setting_current_scores = false;

document.querySelectorAll('input[type=radio]').forEach(function (el) {
    el.addEventListener('change', function () {
        // reset the invalid input search
        window.found_invalid = false;

        // set current score directly and return if this is happening during an employee selection change
        if (window.setting_current_scores) {
            document.getElementById(`badge-${this.name}-current`).textContent = this.value;
            return;
        }

        // get the current score
        let current_score = parseInt(document.getElementById(`badge-${this.name}-current`).textContent);
        if (isNaN(current_score)) {
            current_score = 0;
        }

        // get the new score
        const new_score = this.value;

        // show (or hide) the score delta
        const delta_el = document.getElementById(`${this.name}-delta`);
        const new_badge = document.getElementById(`badge-${this.name}-new`);
        if (current_score === 0) {
            delta_el.classList.remove('show');
            new_badge.classList.remove('badge-danger', 'badge-success');
            new_badge.classList.add('badge-light', 'show');
        } else if (new_score > current_score) {
            delta_el.classList.remove('oi-arrow-bottom');
            delta_el.classList.add('oi-arrow-top', 'show');
            new_badge.classList.remove('badge-danger', 'badge-light');
            new_badge.classList.add('badge-success', 'show');
        } else if (new_score < current_score) {
            delta_el.classList.remove('oi-arrow-top');
            delta_el.classList.add('oi-arrow-bottom', 'show');
            new_badge.classList.remove('badge-light', 'badge-success');
            new_badge.classList.add('badge-danger', 'show');
        } else {
            new_badge.classList.remove('show');
        }

        document.getElementById(`${this.name}-score`).textContent = new_score;
    });
    el.addEventListener('invalid', function () {
        // find the first hidden invalid input and show the tab for it
        if (window.found_invalid) {
            return;
        }
        const pill = document.querySelector(`a[href='#${el.name}']`);
        pill.click();
        window.found_invalid = true;
    });
});

document.getElementById('select-sc').addEventListener('change', function () {
    const selected_option = this.options[this.selectedIndex];

    // clear current score content
    document.querySelectorAll('.current-score').forEach(function (el) {
        el.textContent = '';
    });

    // hide last score stuff
    document.getElementById('last-score').classList.remove('show');
    document.querySelectorAll('.new-score').forEach(function (el) {
        el.classList.remove('show');
    });

    // reset all score selections
    document.querySelectorAll('input[type=radio]').forEach(function (el) {
        el.checked = false;
    });

    // set expected scores
    document.querySelectorAll('.score-selection').forEach(function (el) {
        el.classList.remove('bg-secondary');
    });
    document.querySelectorAll(`.score-${selected_option.dataset.expectedScore}`).forEach(function (el) {
        el.classList.add('bg-secondary');
    });

    window.setting_current_scores = true;

    // select current scores
    const ids = [
        `technical-acumen-${selected_option.dataset.technicalAcumen}`,
        `domain-knowledge-${selected_option.dataset.domainKnowledge}`,
        `discovery-and-qualification-${selected_option.dataset.discoveryAndQualification}`,
        `teamwork-and-collaboration-${selected_option.dataset.teamworkAndCollaboration}`,
        `leadership-skills-${selected_option.dataset.leadershipSkills}`,
        `communication-${selected_option.dataset.communication}`,
        `planning-and-prioritization-${selected_option.dataset.planningAndPrioritization}`,
        `customer-advocacy-${selected_option.dataset.customerAdvocacy}`,
        `attitude-${selected_option.dataset.attitude}`,
        `corporate-citizenship-${selected_option.dataset.corporateCitizenship}`
    ];
    for (const id of ids) {
        const el = document.getElementById(id);
        if (el) {
            el.click();
        }
    }

    window.setting_current_scores = false;

    // show job title
    document.getElementById('job-title-span').textContent = selected_option.dataset.jobTitle;
    document.getElementById('job-title').classList.add('show');

    // show last score timestamp block
    if (selected_option.dataset.scoreTimestamp) {
        document.getElementById('last-score-span').textContent = selected_option.dataset.scoreTimestamp;
        document.getElementById('last-score').classList.add('show');
    }
});
