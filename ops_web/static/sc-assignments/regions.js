$('#modal-edit-assignment').on('show.bs.modal', function (e) {
    let r = $(e.relatedTarget);
    let sc_employee_id = r.attr('data-employee-id');
    let sc_name = r.attr('data-sc-name');
    let region = r.attr('data-region');
    let modal = $(this);
    modal.find('#edit-sc-name').text(sc_name);
    modal.find('#form-edit-sc-employee-id').val(sc_employee_id);
    modal.find('#form-edit-region').val(region);
});
