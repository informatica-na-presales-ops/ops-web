$('#modal-edit-rep').on('show.bs.modal', function (e) {
    let r = $(e.relatedTarget);
    let rep_name = r.attr('data-rep-name');
    let rep_territory = r.attr('data-rep-territory');
    let rep_territory_name = r.attr('data-rep-territory-name');
    let sc_employee_id = r.attr('data-sc-employee-id');
    let modal = $(this);
    modal.find('#edit-rep-name').text(rep_name);
    modal.find('#edit-rep-territory').text(rep_territory);
    modal.find('#form-edit-rep-sc-employee-id').val(sc_employee_id);
    modal.find('#form-edit-rep-territory-name').val(rep_territory_name);
});
