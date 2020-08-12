$('#ecosystem').on('change', function () {
    let nodes = $('.show-on-ecosystem-aws');
    switch (this.value) {
        case 'aws':
            nodes.collapse('show');
            break;
        default:
            nodes.collapse('hide');
    }
});

$('#document').on('change', function () {
    let filename = this.files[0].name;
    let label = $('.custom-file-label', this.parentNode);
    label.text(filename);
});
