// dynamically hide and show form questions

$('input[name="primary-loss-reason"]').on('click', function () {
    let clr = $('#competitive-loss');
    let clr_inputs = $('input[name="competitive-loss-reason"]');
    let tgt_inputs = $('input[name="technology-gap-type"]');
    let ppfr_inputs = $('input[name="perceived-poor-fit-reason"]');
    switch (this.value) {
        case 'key-decision-maker-left':
        case 'project-cancelled':
            clr.collapse('hide');
            clr_inputs.prop('required', false);
            tgt_inputs.prop('required', false);
            ppfr_inputs.prop('required', false);
            break;
        case 'competitive-loss':
            clr.collapse('show');
            clr_inputs.prop('required', true);
            break;
    }
});

$('input[name="competitive-loss-reason"]').on('click',function () {
    let tgt = $('#technology-gap-type');
    let tgt_inputs = $('input[name="technology-gap-type"]');
    let ppfr = $('#perceived-poor-fit-reason');
    let ppfr_inputs = $('input[name="perceived-poor-fit-reason"]');
    switch (this.value) {
        case 'relationship-loss':
        case 'partner-influenced':
            tgt.collapse('hide');
            tgt_inputs.prop('required', false);
            ppfr.collapse('hide');
            ppfr_inputs.prop('required', false);
            break;
        case 'perceived-poor-fit':
            tgt.collapse('hide');
            tgt_inputs.prop('required', false);
            ppfr.collapse('show');
            ppfr_inputs.prop('required', true);
            break;
        case 'technology-gap':
            ppfr.collapse('hide');
            ppfr_inputs.prop('required', false);
            tgt.collapse('show');
            tgt_inputs.prop('required', true);
            break;
    }
});

// change "hide" and "show" on opportunity details as the box is hidden and shown
$('#opportunity-details-body').on('hidden.bs.collapse', function () {
    $('#opportunity-details-toggle-text').text('show');
}).on('shown.bs.collapse', function () {
    $('#opportunity-details-toggle-text').text('hide');
});
