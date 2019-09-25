$('#modal-add-user').on('show.bs.modal', function (e) {
    let button = $(e.relatedTarget);
    let email = button.attr('data-email');
    let current_permissions = button.attr('data-permissions').split(' ');
    let modal = $(this);
    modal.find('#add-user-email').val(email);
    modal.find('.form-check-input').prop('checked', false);
    current_permissions.forEach(function (item) {
        modal.find(`#permission-${item}`).prop('checked', true);
    });
}).on('shown.bs.modal', function () {
    $('#add-user-email').focus();
});
