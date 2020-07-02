// dynamically hide and show form questions

$('input[name="primary-loss-reason"]').on('click', function () {
    let nodes = $('.show-on-tech-gap');
    switch (this.value) {
        case 'price':
        case 'key-decision-maker-left':
        case 'project-cancelled':
        case 'competitive-loss-other':
            nodes.collapse('hide');
            break;
        case 'competitive-loss-tech':
            nodes.collapse('show');
            break;
    }
});

$('#did_poc').on('click', function () {
    let nodes = $('.show-on-did-poc');
    if (this.checked) {
        nodes.collapse('show');
    } else {
        nodes.collapse('hide');
    }
});

$('input[name="poc-outcome"]').on('click', function () {
    let nodes = $('.show-on-bad-poc');
    switch (this.value) {
        case 'tech-win':
        case 'partner-tech-win':
        case 'not-sure':
            nodes.collapse('hide');
            break;
        case 'no-tech-win':
        case 'no-outcome':
        case 'partner-no-tech-win':
            nodes.collapse('show');
            break;
    }
});

// change "hide" and "show" on opportunity details as the box is hidden and shown
$('#opportunity-details-body').on('hidden.bs.collapse', function () {
    $('#opportunity-details-toggle-text').text('show');
}).on('shown.bs.collapse', function () {
    $('#opportunity-details-toggle-text').text('hide');
});
