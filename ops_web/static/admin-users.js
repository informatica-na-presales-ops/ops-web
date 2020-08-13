$('#modal-add-user').on('show.bs.modal', function (e) {
    let button = e.relatedTarget;
    document.getElementById('add-user-email').value = button.dataset.email;
    document.querySelectorAll('.form-check-input').forEach(function (item) {
        item.checked = false;
    });
    button.dataset.permissions.split(' ').forEach(function (item) {
        let el = document.getElementById(`permission-${item}`);
        if (el) {
            el.checked = true;
        }
    });
}).on('shown.bs.modal', function () {
    document.getElementById('add-user-email').focus();
});
