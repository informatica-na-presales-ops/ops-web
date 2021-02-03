$('#modal-choose-track').on('show.bs.modal', function (e) {
    const b = e.relatedTarget;
    document.getElementById('employee-id').value = b.dataset.employeeId;
    document.getElementById('choose-track-employee-name').textContent = b.dataset.employeeName;
    document.querySelectorAll('input[type="radio"]').forEach(function (el) {
        el.checked = (el.value === b.dataset.trackId);
    });
});
