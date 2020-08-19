$('#modal-edit').on('show.bs.modal', function (e) {
    const r = e.relatedTarget;
    document.getElementById('sc-employee-id').value = r.dataset.scEmployeeId;
    document.getElementById('sc-employee-name').value = r.dataset.scEmployeeName;
    document.getElementById('ra-employee-id').value = r.dataset.raEmployeeId;
});
