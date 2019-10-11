$('#modal-image-edit').on('show.bs.modal', function (e) {
    let button = $(e.relatedTarget);
    let image_id = button.attr('data-image-id');
    let image_name = button.attr('data-image-name');
    let image_owner = button.attr('data-image-owner');
    let image_public = (button.attr('data-image-public') === 'true');
    let modal = $(this);
    modal.find('#form-image-edit-image-id').val(image_id);
    modal.find('#form-image-edit-name').val(image_name);
    modal.find('#form-image-edit-owner').val(image_owner);
    modal.find('#form-image-edit-public').prop('checked', image_public);
});

$('#modal-image-launch').on('show.bs.modal', function (e) {
    let button = $(e.relatedTarget);
    let image_id = button.attr('data-image-id');
    let machine_name = button.attr('data-name');
    let modal = $(this);
    modal.find('#form-image-launch-image-id').val(image_id);
    modal.find('#form-image-launch-name').val(machine_name);
});
