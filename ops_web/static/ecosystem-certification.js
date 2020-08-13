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
    let label = $('.custom-file-label', this.parentNode);
    let label_text = label.data('default-text');
    if (this.files.length > 0) {
        label_text = this.files[0].name;
    }
    label.text(label_text);
});
