document.getElementById('ecosystem').addEventListener('change', function () {
    document.getElementById(`default-title-${this.value}`).selected = true;
    const wrapper = document.getElementById('aws-partner-portal-updated-wrapper');
    const input = document.getElementById('aws-partner-portal-updated');
    if (this.value === 'aws') {
        wrapper.classList.add('show');
        input.required = true;
    } else {
        wrapper.classList.remove('show');
        input.required = false;
    }
});

document.getElementById('title').addEventListener('change', function () {
    const wrapper = document.getElementById('custom-title-wrapper');
    const input = document.getElementById('custom-title');
    if (this.value === 'other') {
        wrapper.classList.add('show');
        input.required = true;
    } else {
        wrapper.classList.remove('show');
        input.required = false;
    }
});

document.getElementById('date').addEventListener('change', function () {
    if (this.value) {
        const year = parseInt(this.value.slice(0, 4));
        let expiration_year = year + 2;
        if (document.getElementById('ecosystem').value === 'aws') {
            expiration_year += 1;
        }
        document.getElementById('expiration-date').value = `${expiration_year}-${this.value.slice(5)}`;
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
