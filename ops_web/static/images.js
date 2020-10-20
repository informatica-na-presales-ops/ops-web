$('#modal-image-delete').on('show.bs.modal', function (e) {
    const button = e.relatedTarget;
    document.getElementById('modal-image-delete-image-name').textContent = button.dataset.imageName;
    document.getElementById('form-image-delete-image-id').value = button.dataset.imageId;
});

$('#modal-image-edit').on('show.bs.modal', function (e) {
    const button = e.relatedTarget;
    document.getElementById('form-image-edit-image-id').value = button.dataset.imageId;
    document.getElementById('form-image-edit-name').value = button.dataset.imageName;
    document.getElementById('form-image-edit-owner').value = button.dataset.imageOwner;

    document.getElementById('form-image-edit-application-env-default').selected = true;
    for (const option of document.getElementById('form-image-edit-application-env').options) {
        if (option.value === button.dataset.applicationEnv) {
            option.selected = true;
            break;
        }
    }

    document.getElementById('form-image-edit-application-role').value = button.dataset.applicationRole;
    document.getElementById('form-image-edit-business-unit').value = button.dataset.businessUnit;
    document.getElementById('form-image-edit-public').checked = (button.dataset.imagePublic === 'true')
});

$('#modal-image-launch').on('show.bs.modal', function (e) {
    let button = $(e.relatedTarget);
    let image_id = button.attr('data-image-id');
    let machine_name = button.attr('data-name');
    let modal = $(this);
    modal.find('#form-image-launch-image-id').val(image_id);
    modal.find('#form-image-launch-name').val(machine_name);
});
