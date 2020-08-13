$('#modal-edit-rep').on('show.bs.modal', function (e) {
    let r = e.relatedTarget;
    this.querySelector('#edit-rep-name').textContent = r.dataset.repName;
    this.querySelector('#edit-rep-territory').textContent = r.dataset.repTerritory;
    this.querySelector('#form-edit-rep-sc-employee-id').value = r.dataset.scEmployeeId;
    this.querySelector('#form-edit-rep-territory-name').value = r.dataset.repTerritoryName;
});
