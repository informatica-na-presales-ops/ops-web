$('#modal-edit-rep').on('show.bs.modal', function (e) {
    let r = $(e.relatedTarget);
    let rep_name = r.attr('data-rep-name');
    let rep_territory = r.attr('data-rep-territory');
    let sc_name = r.attr('data-sc-name');
    let modal = $(this);
    modal.find('#edit-rep-name').text(rep_name);
    modal.find('#form-edit-rep-name').val(rep_name);
    modal.find('#edit-rep-territory').text(rep_territory);
    modal.find('#form-edit-rep-sc-name').val(sc_name);
});
