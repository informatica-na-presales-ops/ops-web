let cloud_radios = $('.cloud-radio');

function set_cloud_credential_labels () {
    cloud_radios.each(function () {
        if (this.checked) {
            $('#username-label').text($(this).attr('data-username-label'));
            $('.password-label').text($(this).attr('data-password-label'));
            if (this.id === 'radio-cloud-aws') {
                $('#div-azure-tenant-id').hide();
                $('#cloud-credential-azure-tenant-id').prop('required', false)
            } else {
                $('#div-azure-tenant-id').show();
                $('#cloud-credential-azure-tenant-id').prop('required', true)
            }
        }
    })
}

cloud_radios.change(set_cloud_credential_labels);

$('#modal-cloud-credentials').on('show.bs.modal', function (e) {
    let button = $(e.relatedTarget);
    let id = button.attr('data-id');
    $('#cloud-credentials-id').val(id);
    $('#cloud-credential-description').val(button.attr('data-description'));
    $('#cloud-credential-username').val(button.attr('data-username'));
    let p = $('#cloud-credential-password');
    p.val('');
    $('#cloud-credential-azure-tenant-id').val(button.attr('data-azure-tenant-id'));
    if (id) {
        let c = button.attr('data-cloud');
        $(`#radio-cloud-${c}`).prop('checked', true);
        $('#checkbox-set-password').prop('checked', false);
        $('#div-set-password').show();
        $('#div-password').hide();
    } else {
        $('#radio-cloud-aws').prop('checked', true);
        $('#checkbox-set-password').prop('checked', true);
        $('#div-set-password').hide();
        p.show();
        $('#cloud-credential-delete-button').hide();
    }
    set_cloud_credential_labels();
}).on('shown.bs.modal', function () {
    $('#cloud-credential-description').focus();
});

$('#checkbox-set-password').change(function () {
    if (this.checked) {
        $('#div-password').show();
    } else {
        $('#div-password').hide();
    }
});
