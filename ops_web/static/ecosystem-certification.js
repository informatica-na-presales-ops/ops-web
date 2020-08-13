document.getElementById('ecosystem').addEventListener('change', function () {
    const nodes = document.querySelectorAll('.show-on-ecosystem-aws');
    switch (this.value) {
        case 'aws':
            nodes.forEach(function (el) {
                el.classList.add('show');
            });
            break;
        default:
            nodes.forEach(function (el) {
                el.classList.remove('show');
            });
    }
});

document.getElementById('document').addEventListener('change', function () {
    const label = document.getElementById('document-label');
    let label_text = label.dataset.defaultText;
    if (this.files.length > 0) {
        label_text = this.files[0].name;
    }
    label.textContent = label_text;
});
