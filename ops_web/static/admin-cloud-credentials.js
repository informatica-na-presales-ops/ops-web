function set_cloud_credential_labels () {
    document.querySelectorAll('.cloud-radio').forEach(function (cr) {
        if (cr.checked) {
            document.getElementById('username-label').textContent = cr.dataset.usernameLabel;
            document.querySelectorAll('.password-label').forEach(function (pl) {
                pl.textContent = cr.dataset.passwordLabel;
            });
            if (cr.id === 'radio-cloud-aws') {
                document.getElementById('div-azure-tenant-id').classList.remove('show');
                document.getElementById('cloud-credential-azure-tenant-id').required = false;
            } else {
                document.getElementById('div-azure-tenant-id').classList.add('show');
                document.getElementById('cloud-credential-azure-tenant-id').required = true;
            }
        }
    });
}

document.querySelectorAll('.cloud-radio').forEach(function (el) {
    el.addEventListener('change', set_cloud_credential_labels);
});

$('#modal-cloud-credentials').on('show.bs.modal', function (e) {
    let button = e.relatedTarget;
    let id = button.dataset.id;
    document.getElementById('cloud-credentials-id').value = id;
    document.getElementById('cloud-credential-description').value = button.dataset.description;
    document.getElementById('cloud-credential-username').value = button.dataset.username;
    document.getElementById('cloud-credential-password').value = '';
    document.getElementById('cloud-credential-azure-tenant-id').value = button.dataset.azureTenantId;
    if (id) {
        document.getElementById(`radio-cloud-${button.dataset.cloud}`).checked = true;
        document.getElementById('checkbox-set-password').checked = false;
        document.getElementById('div-set-password').classList.add('show');
        document.getElementById('div-password').classList.remove('show');
        document.getElementById('cloud-credential-delete-button').classList.add('show');
    } else {
        document.getElementById('radio-cloud-aws').checked = true;
        document.getElementById('checkbox-set-password').checked = true;
        document.getElementById('div-set-password').classList.remove('show');
        document.getElementById('div-password').classList.add('show');
        document.getElementById('cloud-credential-delete-button').classList.remove('show');
    }
    set_cloud_credential_labels();
}).on('shown.bs.modal', function () {
    document.getElementById('cloud-credential-description').focus();
});

document.getElementById('checkbox-set-password').addEventListener('change', function () {
    if (this.checked) {
        document.getElementById('div-password').classList.add('show');
    } else {
        document.getElementById('div-password').classList.remove('show');
    }
});
