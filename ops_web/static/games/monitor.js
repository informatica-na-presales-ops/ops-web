$('#modal-reset').on('show.bs.modal', function (e) {
    const button = e.relatedTarget;
    document.getElementById('reset-player-email').value = button.dataset.playerEmail;
    document.querySelectorAll('.reset-player-email').forEach(function (el) {
        el.textContent = button.dataset.playerEmail;
    });
});
