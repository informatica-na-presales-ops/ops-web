document.querySelectorAll('input[type=radio]').forEach(function (el) {
    el.addEventListener('change', function (e) {
        document.getElementById(`badge-${e.target.name}`).textContent = e.target.value;
    });
});

document.getElementById('select-sc').addEventListener('change', function (e) {
    // clear badge content
    document.querySelectorAll('.badge').forEach(function (el) {
        el.textContent = '';
    });

    // reset all score selections
    document.querySelectorAll('input[type=radio]').forEach(function (el) {
        el.checked = false;
    });

    // select current scores
    const selected_option = e.target.options[e.target.selectedIndex];
    const ids = [
        `technical-acumen-${selected_option.dataset.technicalAcumen}`,
        `domain-knowledge-${selected_option.dataset.domainKnowledge}`,
        `discovery-and-qualification-${selected_option.dataset.discoveryAndQualification}`,
        `teamwork-and-collaboration-${selected_option.dataset.teamworkAndCollaboration}`,
        `leadership-skills-${selected_option.dataset.leadershipSkills}`,
        `communicative-${selected_option.dataset.communicative}`,
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
});
